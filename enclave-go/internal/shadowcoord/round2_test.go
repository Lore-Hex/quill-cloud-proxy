package shadowcoord

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speculation"
)

func TestRefreshPanicFailsClosedAndCountsLoss(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	c.RefreshOnce(t.Context(), func(context.Context, []Identity) ([]Result, *Miss) { panic("private callback value") })
	if c.Failures() != 1 || c.Dropped() != 1 {
		t.Fatal("unaccounted worker fault")
	}
	if d := c.Predecision(f.Items[0].LookupDigest, req).Decision(); d.Eligible || d.Reason != "observer-failed" {
		t.Fatal(d)
	}
	c.Suppressed("denial")
	var last Record
	for len(c.Records()) > 0 {
		last = <-c.Records()
	}
	if last.Dropped != 1 {
		t.Fatal("loss missing from records", last)
	}
}
func TestSimulatedMemoryAndRelease(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	c.memory = MaxSimulatedMemory
	if d := c.Predecision(f.Items[0].LookupDigest, req).Decision(); d.Reason != "simulated-memory" || c.slotRetained != 0 || c.unresolved != 0 {
		t.Fatal(d)
	}
	c.memory = 0
	x := c.Predecision(f.Items[0].LookupDigest, req)
	if !x.Decision().Eligible || c.memory != InvocationMemory || c.unresolved != 1 {
		t.Fatal(x.Decision())
	}
	retained := c.slotRetained
	x.Finish()
	x.Finish()
	x.EndAuthorize("", 0)
	if c.memory != 0 || c.unresolved != 0 || c.slotRetained != retained {
		t.Fatal("cleanup released liability or leaked capacity")
	}
}
func TestResolvedDenialScopeAndUnknownCoverage(t *testing.T) {
	for _, workspace := range []string{"w", "other"} {
		c, _, req, r, f := setup(t)
		warm(c, f, r)
		unknown := strings.Repeat("b", 64)
		c.ObserveResolvedVerdict(unknown, 402, "", "", Identity{LookupDigest: unknown, KeyID: "new", WorkspaceID: workspace})
		if len(c.entries) != 1 {
			t.Fatal("invented durable assignment")
		}
		if got := c.Predecision(f.Items[0].LookupDigest, req).Decision(); got.Eligible != (workspace != "w") {
			t.Fatal(got)
		}
	}
}
func TestVerifiedTierCeilingAndClaimShapes(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	claims, err := c.entries[f.Items[0]].cached.verified.Claims()
	if err != nil {
		t.Fatal(err)
	}
	tier, ok := claimInteger(claims["tier"])
	if !ok || tier != 2 {
		t.Fatalf("VerifyGrant numeric type %T", claims["tier"])
	}
	s := c.entries[f.Items[0]]
	s.evidence.Local.Bindings["tier_ceiling_micro"] = int64(100000000)
	s.evidence.WorkspaceRetained = 250000
	if d := c.Predecision(f.Items[0].LookupDigest, req).Decision(); d.Eligible || d.Reason != "simulated-retained-budget" {
		t.Fatal(d)
	}
	for _, v := range []any{int64(2), int(2), json.Number("2")} {
		if n, ok := claimInteger(v); !ok || n != 2 {
			t.Fatal(v)
		}
	}
	for _, v := range []any{nil, "2", 2.5, json.Number("2.5")} {
		if _, ok := claimInteger(v); ok {
			t.Fatal(v)
		}
	}
	for _, v := range []any{nil, "route", map[string]any{"endpoint_id": 3}, map[string]any{"endpoint_id": "e", "provider": "p", "upstream_model": nil}} {
		if _, ok := claimRoute(map[string]any{"route": v}); ok {
			t.Fatal(v)
		}
	}
}
func TestInputLengthRejectsBeforeDecode(t *testing.T) {
	// Valid JSON that would otherwise decode successfully. No allocation is needed
	// to reject it, including when nearly 1 MiB arrives on ordinary ingress.
	raw := []byte(`{"messages":"` + strings.Repeat("x", speculation.MaxInputBytes) + `"}`)
	if n := testing.AllocsPerRun(100, func() {
		if ParseRequest(raw) != nil {
			t.Fatal("oversized decoded")
		}
	}); n != 0 {
		t.Fatal("decoded before length check", n)
	}
	c := New(Shadow, Config{}, nil)
	if d := c.InputMiss().Decision(); d.Reason != "input_bound" || d.Eligible {
		t.Fatal(d)
	}
}
func TestRecordRateAndVisibleLoss(t *testing.T) {
	c, clock, _, _, _ := setup(t)
	for range 1000 {
		c.Suppressed("denial")
	}
	if len(c.records) != 100 || c.Dropped() != 900 {
		t.Fatal(len(c.records), c.Dropped())
	}
	for len(c.records) > 0 {
		<-c.records
	}
	clock.add(time.Second)
	c.Suppressed("denial")
	if r := <-c.records; r.Dropped != 900 {
		t.Fatal(r)
	}
	// Independently exercise bounded queue loss across multiple rate windows.
	for range 6 {
		clock.add(time.Second)
		for range 100 {
			c.Suppressed("denial")
		}
	}
	if len(c.records) != 512 || c.Dropped() != 988 {
		t.Fatal(len(c.records), c.Dropped())
	}
}
func TestGrantReceiptJournalBound(t *testing.T) {
	c, _, req, r, f := setup(t)
	s := c.entries[f.Items[0]]
	for i := range 256 {
		s.receipts[sha256.Sum256([]byte{byte(i)})] = grantReceipt{}
	}
	warm(c, f, r)
	if d := c.Predecision(f.Items[0].LookupDigest, req).Decision(); d.Reason != "grant-journal-capacity" {
		t.Fatal(d)
	}
}

type pausedClock struct {
	now              time.Time
	calls            atomic.Int64
	entered, release chan struct{}
}

func (c *pausedClock) Now() time.Time {
	if c.calls.Add(1) == 2 {
		close(c.entered)
		<-c.release
	}
	return c.now
}
func Test64PredecisionsDoNotHoldLockDuringEvaluation(t *testing.T) {
	c, clock, req, r, f := setup(t)
	warm(c, f, r)
	paused := &pausedClock{now: clock.Now(), entered: make(chan struct{}), release: make(chan struct{})}
	c.clock = paused
	done := make(chan struct{})
	go func() { c.Predecision(f.Items[0].LookupDigest, req); close(done) }()
	<-paused.entered
	var wg sync.WaitGroup
	wg.Add(63)
	for range 63 {
		go func() { defer wg.Done(); c.Predecision(f.Items[0].LookupDigest, req) }()
	}
	others := make(chan struct{})
	go func() { wg.Wait(); close(others) }()
	select {
	case <-others:
	case <-time.After(2 * time.Second):
		close(paused.release)
		<-done
		<-others
		t.Fatal("evaluation serialized other predecisions under coordinator mutex")
	}
	close(paused.release)
	<-done
}
func BenchmarkShadowParseWorstCase(b *testing.B) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{{"max-budget", []byte(`{"x":"` + strings.Repeat("x", speculation.MaxInputBytes-8) + `"}`)}, {"many-containers", []byte(`{"x":[` + strings.Repeat(`{},`, 2727) + `{}]}`)}, {"deep-containers", []byte(`{"x":` + strings.Repeat(`[`, 4090) + `0` + strings.Repeat(`]`, 4090) + `}`)}, {"oversized-1MiB", []byte(`{"x":"` + strings.Repeat("x", 1<<20) + `"}`)}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				ParseRequest(tc.raw)
			}
		})
	}
}
func Benchmark64Predecisions(b *testing.B) {
	// An excluded request against an empty hot set measures the indexed contention
	// floor; the eligible maximum-budget benchmark below measures payload work.
	c := New(Shadow, Config{}, nil)
	b.SetParallelism(64)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Predecision(strings.Repeat("a", 64), speculation.ParsedRequest{})
		}
	})
}
func TestOffModePackageInitAllocations(t *testing.T) {
	if testing.CoverMode() != "" {
		t.Skip("coverage inserts package init counters; measure the uninstrumented binary")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^$")
	cmd.Env = append(os.Environ(), "GODEBUG=inittrace=1", "QUILL_SPECULATIVE_PROVIDER_MODE=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err, string(out))
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "init ") && (strings.Contains(line, "/internal/shadowobserve ") || strings.Contains(line, "/internal/shadowcoord ")) && !strings.Contains(line, "0 bytes, 0 allocs") {
			t.Fatal(line)
		}
	}
}

func BenchmarkShadowRequestAddedWork(b *testing.B) {
	for _, size := range []int{128, 7900, 1 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			c, _, _, r, f := setup(b)
			warm(c, f, r)
			raw := []byte(`{"model":"fixture-text","stream":true,"messages":[{"role":"user","content":"` + strings.Repeat("x", size) + `"}],"max_tokens":512,"provider":{"usage":"Credits"}}`)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				body := ParseRequest(raw)
				var x *Execution
				if body == nil {
					x = c.InputMiss()
				} else {
					x = c.Predecision(f.Items[0].LookupDigest, speculation.ParsedRequest{Body: body, RouteType: "chat.completions", CallerIdempotency: speculation.CaptureCallerIdempotency(false, body)})
				}
				x.StartAuthorize("nonce", "denial")
				x.EndAuthorize("auth", 200)
				x.Finish()
			}
		})
	}
}

func TestResolvedWorkspaceWithoutKeyDoesNotInventAssignment(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	c.ObserveResolvedVerdict(strings.Repeat("b", 64), 402, "billing_denied", "", Identity{WorkspaceID: "w"})
	if d := c.Predecision(f.Items[0].LookupDigest, req).Decision(); d.Reason != "workspace_latched" {
		t.Fatal(d)
	}
	if len(c.entries) != 1 || len(c.byLookup) != 1 || c.bootClosed {
		t.Fatal("scope invented or coverage overclosed")
	}
}

func TestSnapshotRevalidatesNewLookupAmbiguity(t *testing.T) {
	c, clock, req, r, f := setup(t)
	warm(c, f, r)
	paused := &pausedClock{now: clock.Now(), entered: make(chan struct{}), release: make(chan struct{})}
	c.clock = paused
	result := make(chan Decision, 1)
	go func() { result <- c.Predecision(f.Items[0].LookupDigest, req).Decision() }()
	<-paused.entered
	other := f.Items[0]
	other.KeyID = "new-key"
	c.ObserveAuthorized(other)
	close(paused.release)
	if d := <-result; d.Eligible || d.Reason != "snapshot-changed" {
		t.Fatal("admitted stale identity snapshot", d)
	}
	if c.slotRetained != 0 || c.unresolved != 0 {
		t.Fatal("snapshot change consumed capacity")
	}
}

// A valid ordinary Chat shape can carry an unknown, deeply nested JSON field.
// Shadow must include that field in the bounded second parse before excluding it.
func BenchmarkShadowDeepRequestAddedWork(b *testing.B) {
	c, _, _, r, f := setup(b)
	warm(c, f, r)
	raw := []byte(`{"model":"fixture-text","stream":true,"messages":[{"role":"user","content":"x"}],"max_tokens":512,"provider":{"usage":"Credits"},"unknown":` + strings.Repeat("[", 3990) + "0" + strings.Repeat("]", 3990) + "}")
	if len(raw) > speculation.MaxInputBytes {
		b.Fatal("benchmark exceeds bounded decode cohort")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		body := ParseRequest(raw)
		x := c.Predecision(f.Items[0].LookupDigest, speculation.ParsedRequest{Body: body, RouteType: "chat.completions", CallerIdempotency: speculation.CaptureCallerIdempotency(false, body)})
		x.StartAuthorize("nonce", "denial")
		x.EndAuthorize("auth", 200)
		x.Finish()
	}
}

func TestAuthenticatedDenialScopeMemoryBound(t *testing.T) {
	for _, reason := range []string{"billing_denied", "key_limit_exceeded"} {
		c := New(Shadow, Config{}, nil)
		for i := range MaxIdentities + 1 {
			digest := fmt.Sprintf("%064x", i)
			c.ObserveResolvedVerdict(digest, 402, reason, "", Identity{WorkspaceID: strconv.Itoa(i), KeyID: strconv.Itoa(i), LookupDigest: digest})
		}
		if len(c.workspaceClosed) > MaxIdentities || len(c.keyClosed) > MaxIdentities || !c.bootClosed || len(c.entries) != 0 {
			t.Fatal("unbounded denial scope or invented assignment")
		}
	}
}
