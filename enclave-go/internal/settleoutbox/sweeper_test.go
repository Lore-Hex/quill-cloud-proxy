package settleoutbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// sweepStore is an object store in memory with GCS generation semantics:
// create-only and compare-and-set Puts, generation-conditional Deletes,
// sorted paged Lists. It mirrors batch's memoryObjectStore.
type sweepStore struct {
	mu      sync.Mutex
	next    int64
	objects map[string]batch.StoredObject
	// beforePut runs outside the lock before a Put is applied, so a test can
	// interleave a sibling's claim into the window between a Get and a Put.
	beforePut func(name string)
	failPut   map[string]error
}

func newSweepStore() *sweepStore {
	return &sweepStore{next: 1, objects: map[string]batch.StoredObject{}, failPut: map[string]error{}}
}

func (s *sweepStore) Get(_ context.Context, name string) (batch.StoredObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, ok := s.objects[name]
	if !ok {
		return batch.StoredObject{}, batch.ErrNotFound
	}
	object.Data = append([]byte(nil), object.Data...)
	return object, nil
}

func (s *sweepStore) Put(_ context.Context, name string, data []byte, condition batch.PutCondition) (batch.StoredObject, error) {
	if s.beforePut != nil {
		s.beforePut(name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failPut[name]; err != nil {
		return batch.StoredObject{}, err
	}
	existing, exists := s.objects[name]
	if condition.Generation == 0 && exists {
		return batch.StoredObject{}, batch.ErrPrecondition
	}
	if condition.Generation > 0 && (!exists || existing.Generation != condition.Generation) {
		return batch.StoredObject{}, batch.ErrPrecondition
	}
	object := batch.StoredObject{Name: name, Data: append([]byte(nil), data...), Generation: s.next}
	s.next++
	s.objects[name] = object
	return object, nil
}

func (s *sweepStore) Delete(_ context.Context, name string, generation int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, exists := s.objects[name]
	if !exists {
		return nil
	}
	if generation > 0 && existing.Generation != generation {
		return batch.ErrPrecondition
	}
	delete(s.objects, name)
	return nil
}

func (s *sweepStore) List(_ context.Context, prefix string, limit int, pageToken string) ([]batch.ObjectMeta, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0)
	for name := range s.objects {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if pageToken != "" {
		start := sort.SearchStrings(names, pageToken)
		if start < len(names) && names[start] == pageToken {
			start++
		}
		names = names[start:]
	}
	nextPageToken := ""
	if limit > 0 && len(names) > limit {
		nextPageToken = names[limit-1]
		names = names[:limit]
	}
	out := make([]batch.ObjectMeta, 0, len(names))
	for _, name := range names {
		out = append(out, batch.ObjectMeta{Name: name, Generation: s.objects[name].Generation})
	}
	return out, nextPageToken, nil
}

// names lists every object under prefix.
func (s *sweepStore) names(prefix string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0)
	for name := range s.objects {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (s *sweepStore) data(name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, ok := s.objects[name]
	return object.Data, ok
}

func (s *sweepStore) lease(t *testing.T, rest string) (lease, bool) {
	t.Helper()
	data, ok := s.data(leasePrefix + rest)
	if !ok {
		return lease{}, false
	}
	var current lease
	if err := json.Unmarshal(data, &current); err != nil {
		t.Fatalf("decode lease: %v", err)
	}
	return current, true
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type replayFunc func(context.Context, trustedrouter.FrozenTerminal) (*trustedrouter.SettleResult, error)

func (f replayFunc) PostFrozenTerminal(ctx context.Context, t trustedrouter.FrozenTerminal) (*trustedrouter.SettleResult, error) {
	return f(ctx, t)
}

// recordingReplayer answers every replay with answer and records the
// terminals it saw.
type recordingReplayer struct {
	mu     sync.Mutex
	seen   []trustedrouter.FrozenTerminal
	answer func(trustedrouter.FrozenTerminal) (*trustedrouter.SettleResult, error)
}

func (r *recordingReplayer) PostFrozenTerminal(_ context.Context, t trustedrouter.FrozenTerminal) (*trustedrouter.SettleResult, error) {
	r.mu.Lock()
	r.seen = append(r.seen, t)
	r.mu.Unlock()
	if r.answer == nil {
		return &trustedrouter.SettleResult{Settled: true, Disposition: "finalized"}, nil
	}
	return r.answer(t)
}

func (r *recordingReplayer) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

type logBuffer struct {
	mu    sync.Mutex
	lines []string
}

func (l *logBuffer) logf(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *logBuffer) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func controlPlaneStatus(status int) error {
	return &trustedrouter.ControlPlaneError{Path: "/internal/gateway/settle", StatusCode: status, Type: "fixture"}
}

// newTestSweeper is a sweeper on store over replay with a fake clock. The
// interval is not a divisor of the lease, so the backoff's cap at the lease
// is exercised (45 s, 90 s, then 120 s rather than 180 s).
func newTestSweeper(store Store, replay Replayer, clock *fakeClock, logs *logBuffer, owner string) *Sweeper {
	var logf func(string, ...any)
	if logs != nil {
		logf = logs.logf
	}
	sweeper := NewSweeper(store, replay, logf)
	sweeper.now = clock.Now
	sweeper.owner = owner
	sweeper.interval = 45 * time.Second
	sweeper.lease = 2 * time.Minute
	return sweeper
}

// park writes one pending object for body, signed when signer is set, and
// returns its name and its part after the pending prefix.
func park(t *testing.T, store Store, terminal trustedrouter.FrozenTerminal, signer spendlease.DigestSigner) (string, string) {
	t.Helper()
	name, data, err := Encode(Entry{Terminal: terminal, Reason: "retry_exhausted", Attempts: 6}, signer, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), name, data, batch.PutCondition{Generation: 0}); err != nil {
		t.Fatal(err)
	}
	return name, strings.TrimPrefix(name, ObjectPrefix)
}

func bodyFor(authorizationID string) string {
	return `{"authorization_id":"` + authorizationID + `","input_tokens":12,"output_tokens":3}`
}

func refundTerminal(body string) trustedrouter.FrozenTerminal {
	return trustedrouter.FrozenTerminal{Path: "/internal/gateway/refund", Body: []byte(body), BaseURL: "https://trustedrouter.com"}
}

func TestSweepReplaysASignedObjectAndFilesItUnderDone(t *testing.T) {
	store := newSweepStore()
	clock := &fakeClock{now: time.Unix(1_700_000_100, 0)}
	logs := &logBuffer{}
	signer := testSigner(t)
	name, rest := park(t, store, settleTerminal(awkwardBody), signer)
	parked, _ := store.data(name)
	replay := &recordingReplayer{}
	sweeper := newTestSweeper(store, replay, clock, logs, "sweeper_a")

	report, err := sweeper.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report != (Report{Listed: 1, Claimed: 1, Settled: 1}) {
		t.Fatalf("report = %+v", report)
	}
	if replay.count() != 1 {
		t.Fatalf("replays = %d, want 1", replay.count())
	}
	want := Object{}
	if err := json.Unmarshal(parked, &want); err != nil {
		t.Fatal(err)
	}
	got := replay.seen[0]
	if got.Path != "/internal/gateway/settle" || string(got.Body) != awkwardBody || got.BaseURL != "https://trustedrouter.com" || got.BootAuth != want.BootAuth || got.BootAuth == "" {
		t.Fatalf("replayed terminal = %+v", got)
	}
	if names := store.names(ObjectPrefix); len(names) != 0 {
		t.Fatalf("pending still holds %v", names)
	}
	done, ok := store.data(DonePrefix + rest)
	if !ok || string(done) != string(parked) {
		t.Fatalf("done object missing or rewritten: ok=%t", ok)
	}
	if _, ok := store.lease(t, rest); ok {
		t.Fatal("lease left behind after filing")
	}
	if !strings.Contains(logs.all(), `outcome="settled"`) || !strings.Contains(logs.all(), `target="`+DonePrefix+rest+`"`) {
		t.Fatalf("logs:\n%s", logs.all())
	}
}

// Every router answer lands where §9.2 says: 2xx done, 404 and 409 dead,
// 401 and 403 quarantine. Other 4xx the contract does not name: 408 and 429
// retry, the rest are deterministic and go to dead.
func TestSweepFilesEachRouterAnswerWhereTheContractSays(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		prefix string
		report Report
	}{
		{"settled", nil, DonePrefix, Report{Listed: 1, Claimed: 1, Settled: 1}},
		{"404_unknown_authorization", controlPlaneStatus(404), DeadPrefix, Report{Listed: 1, Claimed: 1, Dead: 1}},
		{"409_retired_kind", controlPlaneStatus(409), DeadPrefix, Report{Listed: 1, Claimed: 1, Dead: 1}},
		{"401_refused", controlPlaneStatus(401), QuarantinePrefix, Report{Listed: 1, Claimed: 1, Quarantined: 1}},
		{"403_refused", controlPlaneStatus(403), QuarantinePrefix, Report{Listed: 1, Claimed: 1, Quarantined: 1}},
		{"422_rejected", controlPlaneStatus(422), DeadPrefix, Report{Listed: 1, Claimed: 1, Dead: 1}},
		{"429_throttled", controlPlaneStatus(429), ObjectPrefix, Report{Listed: 1, Claimed: 1, Retried: 1}},
		{"503_server_error", controlPlaneStatus(503), ObjectPrefix, Report{Listed: 1, Claimed: 1, Retried: 1}},
		{"transport", errors.New("dial tcp: connection refused"), ObjectPrefix, Report{Listed: 1, Claimed: 1, Retried: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newSweepStore()
			clock := &fakeClock{now: time.Unix(1_700_000_100, 0)}
			name, rest := park(t, store, settleTerminal(bodyFor("auth_"+tc.name)), testSigner(t))
			parked, _ := store.data(name)
			replay := &recordingReplayer{answer: func(trustedrouter.FrozenTerminal) (*trustedrouter.SettleResult, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return &trustedrouter.SettleResult{AlreadySettled: true}, nil
			}}
			sweeper := newTestSweeper(store, replay, clock, nil, "sweeper_a")
			report, err := sweeper.Sweep(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if report != tc.report {
				t.Fatalf("report = %+v, want %+v", report, tc.report)
			}
			if replay.count() != 1 {
				t.Fatalf("replays = %d", replay.count())
			}
			moved, ok := store.data(tc.prefix + rest)
			if !ok || string(moved) != string(parked) {
				t.Fatalf("object not under %s with its bytes unchanged (ok=%t)", tc.prefix, ok)
			}
			for _, prefix := range []string{ObjectPrefix, DonePrefix, DeadPrefix, QuarantinePrefix} {
				if prefix == tc.prefix {
					continue
				}
				if names := store.names(prefix); len(names) != 0 {
					t.Fatalf("object also under %s: %v", prefix, names)
				}
			}
			_, leased := store.lease(t, rest)
			if leased != (tc.prefix == ObjectPrefix) {
				t.Fatalf("lease present = %t after %s", leased, tc.name)
			}
		})
	}
}

// A failed replay releases the lease with a backoff that doubles per attempt
// and never exceeds the lease; the object is not replayed again before the
// backoff passes, and a later success files it and drops the lease.
func TestSweepRetriesUnderABackoffBoundedByTheLease(t *testing.T) {
	store := newSweepStore()
	clock := &fakeClock{now: time.Unix(1_700_000_100, 0)}
	_, rest := park(t, store, settleTerminal(bodyFor("auth_retry")), testSigner(t))
	var fail atomic.Bool
	fail.Store(true)
	replay := &recordingReplayer{answer: func(trustedrouter.FrozenTerminal) (*trustedrouter.SettleResult, error) {
		if fail.Load() {
			return nil, controlPlaneStatus(502)
		}
		return &trustedrouter.SettleResult{Settled: true}, nil
	}}
	sweeper := newTestSweeper(store, replay, clock, nil, "sweeper_a")
	ctx := context.Background()

	wantBackoff := []time.Duration{45 * time.Second, 90 * time.Second, 2 * time.Minute, 2 * time.Minute}
	for attempt, backoff := range wantBackoff {
		if _, err := sweeper.Sweep(ctx); err != nil {
			t.Fatal(err)
		}
		if replay.count() != attempt+1 {
			t.Fatalf("attempt %d: replays = %d", attempt+1, replay.count())
		}
		held, ok := store.lease(t, rest)
		if !ok || held.Owner != "" || held.Attempts != attempt+1 || held.Until != clock.Now().Add(backoff).UnixMilli() {
			t.Fatalf("attempt %d: lease = %+v, ok=%t, want backoff %s", attempt+1, held, ok, backoff)
		}
		// Inside the backoff nothing happens.
		clock.Advance(backoff - time.Second)
		report, err := sweeper.Sweep(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if replay.count() != attempt+1 || report.Skipped != 1 || report.Claimed != 0 {
			t.Fatalf("attempt %d: replayed inside backoff (replays=%d report=%+v)", attempt+1, replay.count(), report)
		}
		clock.Advance(time.Second)
	}
	fail.Store(false)
	report, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Settled != 1 || replay.count() != len(wantBackoff)+1 {
		t.Fatalf("final report = %+v replays = %d", report, replay.count())
	}
	if _, ok := store.data(DonePrefix + rest); !ok {
		t.Fatal("object not filed under done after the retry succeeded")
	}
	if _, ok := store.lease(t, rest); ok {
		t.Fatal("lease left behind")
	}
}

// An object the sweeper cannot trust is never replayed: no boot_auth, a
// malformed header, or a header for another kid than the object names. It is
// quarantined with its bytes unchanged and the kid logged.
func TestSweepQuarantinesUnsignedObjectsWithoutReplaying(t *testing.T) {
	signer := testSigner(t)
	for _, tc := range []struct {
		name   string
		mutate func(*Object)
		reason string
	}{
		{"no_boot_auth", func(o *Object) { o.BootAuth = ""; o.BootKID = "" }, "unsigned"},
		{"kid_only_no_sig", func(o *Object) { o.BootAuth = "kid=" + o.BootKID + ",sig=" }, "unsigned"},
		{"malformed", func(o *Object) { o.BootAuth = "bearer abc" }, "unsigned"},
		{"kid_mismatch", func(o *Object) { o.BootKID = "boot_other" }, "boot_kid_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newSweepStore()
			logs := &logBuffer{}
			_, data, err := Encode(Entry{Terminal: settleTerminal(bodyFor("auth_" + tc.name)), Reason: "evicted", Attempts: 1}, signer, time.Unix(1_700_000_000, 0))
			if err != nil {
				t.Fatal(err)
			}
			var object Object
			if err := json.Unmarshal(data, &object); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&object)
			data, err = json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(data); err != nil {
				t.Fatalf("fixture must decode: %v", err)
			}
			name := ObjectName(object.Kind, object.AuthorizationID, object.Body)
			if _, err := store.Put(context.Background(), name, data, batch.PutCondition{Generation: 0}); err != nil {
				t.Fatal(err)
			}
			rest := strings.TrimPrefix(name, ObjectPrefix)
			replay := &recordingReplayer{}
			sweeper := newTestSweeper(store, replay, &fakeClock{now: time.Unix(1_700_000_100, 0)}, logs, "sweeper_a")
			report, err := sweeper.Sweep(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if replay.count() != 0 {
				t.Fatalf("an untrusted object was replayed %d times", replay.count())
			}
			if report != (Report{Listed: 1, Claimed: 1, Quarantined: 1}) {
				t.Fatalf("report = %+v", report)
			}
			moved, ok := store.data(QuarantinePrefix + rest)
			if !ok || string(moved) != string(data) {
				t.Fatalf("quarantined object missing or rewritten (ok=%t)", ok)
			}
			if names := store.names(ObjectPrefix); len(names) != 0 {
				t.Fatalf("pending still holds %v", names)
			}
			if _, ok := store.lease(t, rest); ok {
				t.Fatal("lease left behind")
			}
			if all := logs.all(); !strings.Contains(all, `reason="`+tc.reason+`"`) || !strings.Contains(all, `kid="`+object.BootKID+`"`) {
				t.Fatalf("logs:\n%s", all)
			}
		})
	}
}

// An envelope Decode refuses (another version, a non-terminal path, a body
// whose digest does not match) is quarantined verbatim, never replayed.
func TestSweepQuarantinesUndecodableObjectsVerbatim(t *testing.T) {
	signer := testSigner(t)
	for _, tc := range []struct {
		name   string
		mutate func(*Object)
	}{
		{"version", func(o *Object) { o.Version = 2 }},
		{"path", func(o *Object) { o.Path = "/internal/gateway/authorize" }},
		{"digest", func(o *Object) { o.Body = append(o.Body, ' ') }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newSweepStore()
			_, data, err := Encode(Entry{Terminal: settleTerminal(bodyFor("auth_" + tc.name)), Reason: "shutdown", Attempts: 1}, signer, time.Unix(1_700_000_000, 0))
			if err != nil {
				t.Fatal(err)
			}
			var object Object
			if err := json.Unmarshal(data, &object); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&object)
			data, err = json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(data); err == nil {
				t.Fatal("fixture must not decode")
			}
			rest := "settle/auth_" + tc.name + "/0123456789abcdef.json"
			if _, err := store.Put(context.Background(), ObjectPrefix+rest, data, batch.PutCondition{Generation: 0}); err != nil {
				t.Fatal(err)
			}
			replay := &recordingReplayer{}
			sweeper := newTestSweeper(store, replay, &fakeClock{now: time.Unix(1_700_000_100, 0)}, nil, "sweeper_a")
			report, err := sweeper.Sweep(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if replay.count() != 0 || report.Quarantined != 1 {
				t.Fatalf("replays = %d report = %+v", replay.count(), report)
			}
			moved, ok := store.data(QuarantinePrefix + rest)
			if !ok || string(moved) != string(data) {
				t.Fatalf("quarantined bytes differ (ok=%t)", ok)
			}
			if names := store.names(ObjectPrefix); len(names) != 0 {
				t.Fatalf("pending still holds %v", names)
			}
		})
	}
}

// Two sweepers that reach the same object at the same moment: the lease is
// a create-only write, so exactly one replays. Deterministic interleaving:
// while A is between reading no lease and creating one, B runs a whole sweep.
// When B's replay fails, B leaves a backoff lease and A's create answers
// 412: A sends nothing. When B's replay succeeds, B files the object and
// drops the lease; A's create then succeeds on an object that is gone, and
// A drops its orphan lease without sending anything.
func TestTwoSweepersRacingOneObjectReplayExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bErr    error
		aReport Report
		prefix  string
	}{
		{"sibling_holds_lease", controlPlaneStatus(503), Report{Listed: 1, Skipped: 1}, ObjectPrefix},
		{"sibling_filed", nil, Report{Listed: 1, Claimed: 1, Skipped: 1}, DonePrefix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newSweepStore()
			clock := &fakeClock{now: time.Unix(1_700_000_100, 0)}
			_, rest := park(t, store, settleTerminal(bodyFor("auth_race")), testSigner(t))
			replayA := &recordingReplayer{}
			replayB := &recordingReplayer{answer: func(trustedrouter.FrozenTerminal) (*trustedrouter.SettleResult, error) {
				if tc.bErr != nil {
					return nil, tc.bErr
				}
				return &trustedrouter.SettleResult{Settled: true}, nil
			}}
			a := newTestSweeper(store, replayA, clock, nil, "sweeper_a")
			b := newTestSweeper(store, replayB, clock, nil, "sweeper_b")
			var interposed atomic.Bool
			store.beforePut = func(name string) {
				if name == leasePrefix+rest && interposed.CompareAndSwap(false, true) {
					if _, err := b.Sweep(context.Background()); err != nil {
						t.Error(err)
					}
				}
			}
			report, err := a.Sweep(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !interposed.Load() {
				t.Fatal("B never ran inside A's claim window")
			}
			if replayA.count() != 0 || replayB.count() != 1 {
				t.Fatalf("replays: a=%d b=%d, want exactly one in total, by b", replayA.count(), replayB.count())
			}
			if report != tc.aReport {
				t.Fatalf("a's report = %+v, want %+v", report, tc.aReport)
			}
			if _, ok := store.data(tc.prefix + rest); !ok {
				t.Fatalf("object not under %s", tc.prefix)
			}
			held, leased := store.lease(t, rest)
			if tc.bErr != nil && (!leased || held.Owner != "" || held.Attempts != 1) {
				t.Fatalf("b's backoff lease = %+v leased=%t", held, leased)
			}
			if tc.bErr == nil && leased {
				t.Fatalf("a left an orphan lease: %+v", held)
			}
		})
	}
}

// Many objects, two sweepers in parallel, each sweeping until the prefix is
// empty: every object is replayed exactly once.
func TestTwoSweepersInParallelReplayEveryObjectOnce(t *testing.T) {
	store := newSweepStore()
	clock := &fakeClock{now: time.Unix(1_700_000_100, 0)}
	signer := testSigner(t)
	const objects = 40
	for i := 0; i < objects; i++ {
		park(t, store, settleTerminal(bodyFor(fmt.Sprintf("auth_%02d", i))), signer)
	}
	var mu sync.Mutex
	replays := map[string]int{}
	slow := replayFunc(func(_ context.Context, terminal trustedrouter.FrozenTerminal) (*trustedrouter.SettleResult, error) {
		time.Sleep(time.Millisecond)
		mu.Lock()
		replays[string(terminal.Body)]++
		mu.Unlock()
		return &trustedrouter.SettleResult{Settled: true}, nil
	})
	var wait sync.WaitGroup
	for _, owner := range []string{"sweeper_a", "sweeper_b"} {
		sweeper := newTestSweeper(store, slow, clock, nil, owner)
		sweeper.pageSize = 7
		wait.Add(1)
		go func() {
			defer wait.Done()
			for i := 0; i < 20 && len(store.names(ObjectPrefix)) > 0; i++ {
				if _, err := sweeper.Sweep(context.Background()); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wait.Wait()
	if names := store.names(ObjectPrefix); len(names) != 0 {
		t.Fatalf("pending still holds %d objects", len(names))
	}
	if len(replays) != objects {
		t.Fatalf("%d distinct bodies replayed, want %d", len(replays), objects)
	}
	for body, n := range replays {
		if n != 1 {
			t.Fatalf("body replayed %d times: %s", n, body)
		}
	}
	if done := store.names(DonePrefix); len(done) != objects {
		t.Fatalf("done holds %d, want %d", len(done), objects)
	}
	if leases := store.names(leasePrefix); len(leases) != 0 {
		t.Fatalf("leases left behind: %v", leases)
	}
}

// A sweeper that stalls inside its replay keeps the lease until it expires;
// a sibling skips the object until then and takes it over afterwards. When
// the stalled sweeper finally returns, its filing finds the object already
// moved and its lease already gone, and tolerates both.
func TestSweepLeaseExpiryHandsAStalledObjectToASibling(t *testing.T) {
	store := newSweepStore()
	clock := &fakeClock{now: time.Unix(1_700_000_100, 0)}
	name, rest := park(t, store, settleTerminal(bodyFor("auth_stall")), testSigner(t))
	parked, _ := store.data(name)
	started := make(chan struct{})
	release := make(chan struct{})
	stalled := replayFunc(func(context.Context, trustedrouter.FrozenTerminal) (*trustedrouter.SettleResult, error) {
		close(started)
		<-release
		return &trustedrouter.SettleResult{Settled: true}, nil
	})
	a := newTestSweeper(store, stalled, clock, nil, "sweeper_a")
	replayB := &recordingReplayer{}
	b := newTestSweeper(store, replayB, clock, nil, "sweeper_b")

	aDone := make(chan Report, 1)
	go func() {
		report, err := a.Sweep(context.Background())
		if err != nil {
			t.Error(err)
		}
		aDone <- report
	}()
	<-started
	report, err := b.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if replayB.count() != 0 || report != (Report{Listed: 1, Skipped: 1}) {
		t.Fatalf("b replayed under a's live lease: replays=%d report=%+v", replayB.count(), report)
	}
	clock.Advance(a.lease + time.Second)
	report, err = b.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if replayB.count() != 1 || report != (Report{Listed: 1, Claimed: 1, Settled: 1}) {
		t.Fatalf("b did not take over the expired lease: replays=%d report=%+v", replayB.count(), report)
	}
	held, ok := store.lease(t, rest)
	if ok {
		t.Fatalf("lease still present after b filed: %+v", held)
	}
	close(release)
	aReport := <-aDone
	if aReport != (Report{Listed: 1, Claimed: 1, Settled: 1}) {
		t.Fatalf("a's late report = %+v", aReport)
	}
	done, ok := store.data(DonePrefix + rest)
	if !ok || string(done) != string(parked) {
		t.Fatalf("done object missing or rewritten (ok=%t)", ok)
	}
	if names := store.names(ObjectPrefix); len(names) != 0 {
		t.Fatalf("pending still holds %v", names)
	}
	if leases := store.names(leasePrefix); len(leases) != 0 {
		t.Fatalf("leases left behind: %v", leases)
	}
}

// Through the real control-plane client: the router receives the object's
// exact bytes at base_url+path, the boot-auth header verbatim, and no
// settlement mode or shadow header; its answers classify as the contract
// says.
func TestSweepPostsTheExactBytesAndBootAuthToTheRouter(t *testing.T) {
	type received struct {
		path   string
		body   string
		header http.Header
	}
	for _, tc := range []struct {
		name     string
		status   int
		terminal func(string) trustedrouter.FrozenTerminal
		prefix   string
		posts    int
	}{
		{"settle_200", http.StatusOK, settleTerminal, DonePrefix, 1},
		{"refund_200", http.StatusOK, refundTerminal, DonePrefix, 1},
		{"settle_404", http.StatusNotFound, settleTerminal, DeadPrefix, 1},
		{"settle_409", http.StatusConflict, settleTerminal, DeadPrefix, 1},
		{"settle_403", http.StatusForbidden, settleTerminal, QuarantinePrefix, 1},
		// A pinned settle for a named authorization retries 5xx inside the
		// client's own budget (3 attempts); the sweeper then backs off.
		{"settle_503", http.StatusServiceUnavailable, settleTerminal, ObjectPrefix, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var got []received
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				mu.Lock()
				got = append(got, received{path: r.URL.Path, body: string(raw), header: r.Header.Clone()})
				mu.Unlock()
				if tc.status != http.StatusOK {
					http.Error(w, `{"error":{"message":"fixture","type":"fixture"}}`, tc.status)
					return
				}
				_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":15,"disposition":"finalized"}}`)
			}))
			t.Cleanup(server.Close)
			client := trustedrouter.New(server.URL, "internal-test", &http.Client{})
			if err := client.ConfigurationError(); err != nil {
				t.Fatal(err)
			}
			store := newSweepStore()
			terminal := tc.terminal(awkwardBody)
			terminal.BaseURL = server.URL
			name, rest := park(t, store, terminal, testSigner(t))
			parked, _ := store.data(name)
			var object Object
			if err := json.Unmarshal(parked, &object); err != nil {
				t.Fatal(err)
			}
			sweeper := newTestSweeper(store, client, &fakeClock{now: time.Unix(1_700_000_100, 0)}, nil, "sweeper_a")
			if _, err := sweeper.Sweep(context.Background()); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(got) != tc.posts {
				t.Fatalf("router received %d posts, want %d", len(got), tc.posts)
			}
			for _, post := range got {
				if post.path != terminal.Path {
					t.Fatalf("posted to %q, want %q", post.path, terminal.Path)
				}
				if post.body != awkwardBody {
					t.Fatalf("router received %q, want the frozen bytes %q", post.body, awkwardBody)
				}
				if header := post.header.Get(spendlease.BootAuthHeader); header != object.BootAuth || header == "" {
					t.Fatalf("boot auth header = %q, want the object's %q", header, object.BootAuth)
				}
				for _, forbidden := range []string{"X-TR-Settlement-Mode", "X-TR-Settlement-Shadow", "X-TR-Settlement-Shadow-Policy"} {
					if _, present := post.header[forbidden]; present {
						t.Fatalf("replay carried %s", forbidden)
					}
				}
			}
			if _, ok := store.data(tc.prefix + rest); !ok {
				t.Fatalf("object not under %s", tc.prefix)
			}
		})
	}
}

// With a page smaller than the backlog, successive sweeps continue the
// listing and clear everything.
func TestSweepPagesAcrossSweeps(t *testing.T) {
	store := newSweepStore()
	clock := &fakeClock{now: time.Unix(1_700_000_100, 0)}
	signer := testSigner(t)
	for i := 0; i < 5; i++ {
		park(t, store, settleTerminal(bodyFor(fmt.Sprintf("auth_page_%d", i))), signer)
	}
	replay := &recordingReplayer{}
	sweeper := newTestSweeper(store, replay, clock, nil, "sweeper_a")
	sweeper.pageSize = 2
	for i := 0; i < 3; i++ {
		if _, err := sweeper.Sweep(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if replay.count() != 5 || len(store.names(ObjectPrefix)) != 0 || len(store.names(DonePrefix)) != 5 {
		t.Fatalf("replays=%d pending=%v done=%d", replay.count(), store.names(ObjectPrefix), len(store.names(DonePrefix)))
	}
}

// Start sweeps on its interval until the context ends.
func TestStartSweepsOnItsInterval(t *testing.T) {
	store := newSweepStore()
	_, rest := park(t, store, settleTerminal(bodyFor("auth_loop")), testSigner(t))
	replay := &recordingReplayer{}
	sweeper := NewSweeper(store, replay, nil)
	sweeper.interval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sweeper.Start(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := store.data(DonePrefix + rest); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the loop never filed the object")
		}
		time.Sleep(time.Millisecond)
	}
	if replay.count() != 1 {
		t.Fatalf("replays = %d", replay.count())
	}
}

// Sweeper logs name objects, authorizations, kids and outcomes; never the
// body bytes or the signature.
func TestSweepLogsNeitherBodyNorBootAuth(t *testing.T) {
	store := newSweepStore()
	logs := &logBuffer{}
	signer := testSigner(t)
	name, _ := park(t, store, settleTerminal(awkwardBody), signer)
	parked, _ := store.data(name)
	var object Object
	if err := json.Unmarshal(parked, &object); err != nil {
		t.Fatal(err)
	}
	_, sig, _ := strings.Cut(object.BootAuth, ",sig=")
	park(t, store, settleTerminal(bodyFor("auth_unsigned")), nil)
	replay := &recordingReplayer{answer: func(trustedrouter.FrozenTerminal) (*trustedrouter.SettleResult, error) {
		return nil, controlPlaneStatus(500)
	}}
	sweeper := newTestSweeper(store, replay, &fakeClock{now: time.Unix(1_700_000_100, 0)}, logs, "sweeper_a")
	if _, err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	all := logs.all()
	if all == "" {
		t.Fatal("nothing logged")
	}
	for _, secret := range []string{awkwardBody, "actual_output_tokens", sig, "input_tokens"} {
		if strings.Contains(all, secret) {
			t.Fatalf("log carries %q:\n%s", secret, all)
		}
	}
	if !strings.Contains(all, `auth_id="auth_outbox_1"`) || !strings.Contains(all, `kid="`+signer.Kid()+`"`) {
		t.Fatalf("logs lack the identifiers an operator needs:\n%s", all)
	}
}
