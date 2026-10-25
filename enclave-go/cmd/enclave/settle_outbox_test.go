package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/batch"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/settleoutbox"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// outboxTestStore is a create-only object store in memory.
type outboxTestStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	order   []string
}

func newOutboxTestStore() *outboxTestStore {
	return &outboxTestStore{objects: map[string][]byte{}}
}

func (s *outboxTestStore) Put(_ context.Context, name string, data []byte, condition batch.PutCondition) (batch.StoredObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if condition.Generation != 0 {
		return batch.StoredObject{}, errors.New("outbox must create, not overwrite")
	}
	if _, exists := s.objects[name]; exists {
		return batch.StoredObject{}, batch.ErrPrecondition
	}
	s.objects[name] = append([]byte(nil), data...)
	s.order = append(s.order, name)
	return batch.StoredObject{Name: name, Data: data, Generation: int64(len(s.order))}, nil
}

// The writer only creates. The sweeper's methods are not reached from
// these tests; a call is a test failure, not a silent no-op.
func (s *outboxTestStore) Get(context.Context, string) (batch.StoredObject, error) {
	return batch.StoredObject{}, errors.New("outboxTestStore: Get is not expected here")
}

func (s *outboxTestStore) Delete(context.Context, string, int64) error {
	return errors.New("outboxTestStore: Delete is not expected here")
}

func (s *outboxTestStore) List(context.Context, string, int, string) ([]batch.ObjectMeta, string, error) {
	return nil, "", errors.New("outboxTestStore: List is not expected here")
}

// objects waits until want objects exist and returns them decoded, in write
// order.
func (s *outboxTestStore) parked(t *testing.T, want int) []settleoutbox.Object {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.order)
		s.mu.Unlock()
		if n >= want || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.order) != want {
		t.Fatalf("outbox holds %d objects, want %d: %v", len(s.order), want, s.order)
	}
	decoded := make([]settleoutbox.Object, 0, len(s.order))
	for _, name := range s.order {
		object, err := settleoutbox.Decode(s.objects[name])
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		decoded = append(decoded, object)
	}
	return decoded
}

func outboxTestSigner(t *testing.T) *receipt.Signer {
	t.Helper()
	signer, err := receipt.NewSignerFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// outboxTestWriter is a started writer over store, flushed at test end.
func outboxTestWriter(t *testing.T, store *outboxTestStore, signer *receipt.Signer) *settleoutbox.Writer {
	t.Helper()
	plan := prepareSettleOutbox("outbox-bucket", func(string) (settleoutbox.Store, error) { return store, nil })
	if !plan.Configured() {
		t.Fatal("prepareSettleOutbox returned nil for a configured bucket")
	}
	// A nil *receipt.Signer must not become a non-nil interface.
	var digestSigner spendlease.DigestSigner
	if signer != nil {
		digestSigner = signer
	}
	writer := startSettleOutbox(t.Context(), plan, digestSigner)
	if writer == nil {
		t.Fatal("startSettleOutbox returned nil for a prepared plan")
	}
	return writer
}

// The writer signs with the key a registration path was started for, and with
// nothing when this boot registers nowhere.
func TestOutboxSignsOnlyWithARegisteredBootKey(t *testing.T) {
	gateway, _ := frozenRetryGateway(t, nil)
	signer := outboxTestSigner(t)
	for _, tc := range []struct {
		name     string
		register func(*trustedrouter.Client)
		signed   bool
	}{
		{"unregistered", func(*trustedrouter.Client) {}, false},
		{"stage_d", func(c *trustedrouter.Client) { c.ConfigureStageDBoot(signer) }, true},
		// A shadow-only boot's authorize carries no boot auth, so nothing it
		// signed could be verified: its objects stay unsigned.
		{"shadow_only", func(c *trustedrouter.Client) { c.ConfigureShadowBoot(signer) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := trustedrouter.New("http://127.0.0.1:18080", "internal", &http.Client{})
			tc.register(client)
			store := newOutboxTestStore()
			plan := prepareSettleOutbox("outbox-bucket", func(string) (settleoutbox.Store, error) { return store, nil })
			writer := startSettleOutbox(t.Context(), plan, client.RegisteredBootSigner())
			q := &settlementRetryQueue{}
			q.SetOutbox(writer)
			q.Enqueue(outboxSettleJob(gateway))
			object := store.parked(t, 1)[0]
			if (object.BootAuth != "") != tc.signed || (tc.signed && object.BootKID != signer.Kid()) || (!tc.signed && object.BootKID != "") {
				t.Fatalf("boot_auth = %q kid = %q, want signed=%t", object.BootAuth, object.BootKID, tc.signed)
			}
		})
	}
}

func outboxSettleJob(gateway *trustedrouter.Client) settlementRetryJob {
	return settlementRetryJob{
		trGateway:     gateway,
		authorization: frozenRetryPrivateAuthorization(0, true),
		usage:         frozenRetryPrivateUsage(),
		requestLogID:  frozenRetryRequestLogID,
		cause:         errors.New("fixture 503"),
	}
}

func TestRetryExhaustionParksTheFrozenTerminal(t *testing.T) {
	gateway, captured := frozenRetryGateway(t, func(int) int { return http.StatusServiceUnavailable })
	store := newOutboxTestStore()
	signer := outboxTestSigner(t)
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 2, baseDelay: time.Millisecond, maxDelay: time.Millisecond}
	q.SetOutbox(outboxTestWriter(t, store, signer))
	q.Start(t.Context())

	if !q.Enqueue(outboxSettleJob(gateway)) {
		t.Fatal("Enqueue refused")
	}
	objects := store.parked(t, 1)
	object := objects[0]

	posted := captured()
	// Each attempt is 3 tries at the pinned authority; two attempts posted.
	if len(posted) < 2 {
		t.Fatalf("router saw %d posts", len(posted))
	}
	for _, capture := range posted {
		if capture.path != "/internal/gateway/settle" || capture.body != posted[0].body {
			t.Fatalf("router posts differ: %+v", posted)
		}
	}
	if string(object.Body) != posted[0].body {
		t.Fatalf("parked body differs from what the router received:\n got %s\nwant %s", object.Body, posted[0].body)
	}
	if object.Kind != settleoutbox.KindSettle || object.Path != "/internal/gateway/settle" || object.AuthorizationID != "auth_frozen_retry" {
		t.Fatalf("object = %+v", object)
	}
	if object.Reason != "retry_exhausted" || object.Attempts != 2 {
		t.Fatalf("reason = %q attempts = %d", object.Reason, object.Attempts)
	}
	if !strings.HasPrefix(object.BaseURL, "http://127.0.0.1:") {
		t.Fatalf("base_url = %q, want the pinned authority", object.BaseURL)
	}
	if object.BootKID != signer.Kid() || !strings.HasPrefix(object.BootAuth, "kid="+signer.Kid()+",sig=") {
		t.Fatalf("boot auth = %q kid = %q", object.BootAuth, object.BootKID)
	}
	for _, private := range []string{"user-private", "session-private", "trace-value-private", "metadata-value-private", "referer-private", "category-private"} {
		if bytes.Contains(object.Body, []byte(private)) {
			t.Fatalf("parked body carries %q", private)
		}
	}
}

func TestRetryExhaustionWithoutAnOutboxIsALogLineAsBefore(t *testing.T) {
	gateway, captured := frozenRetryGateway(t, func(int) int { return http.StatusServiceUnavailable })
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 1}
	q.Start(t.Context())
	if !q.Enqueue(outboxSettleJob(gateway)) {
		t.Fatal("Enqueue refused")
	}
	waitCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := q.WaitForIdle(waitCtx); err != nil {
		t.Fatal(err)
	}
	if len(captured()) == 0 {
		t.Fatal("nothing posted")
	}
}

func TestEvictedJobIsParked(t *testing.T) {
	gateway, _ := frozenRetryGateway(t, nil)
	store := newOutboxTestStore()
	// Capacity one and no worker: the second enqueue evicts the first.
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 1), maxAttempts: 3}
	q.SetOutbox(outboxTestWriter(t, store, nil))

	first := outboxSettleJob(gateway)
	first.usage.OutputTokens = 1
	second := outboxSettleJob(gateway)
	second.usage.OutputTokens = 2
	if !q.Enqueue(first) || !q.Enqueue(second) {
		t.Fatal("Enqueue refused")
	}
	objects := store.parked(t, 1)
	if objects[0].Reason != "evicted" || !bytes.Contains(objects[0].Body, []byte(`"actual_output_tokens":1`)) {
		t.Fatalf("parked object = %+v body = %s", objects[0], objects[0].Body)
	}
	if objects[0].BootAuth != "" {
		t.Fatalf("boot auth = %q without a signer", objects[0].BootAuth)
	}
	if len(q.jobs) != 1 {
		t.Fatalf("queued = %d", len(q.jobs))
	}
}

func TestDisabledQueueParks(t *testing.T) {
	gateway, _ := frozenRetryGateway(t, nil)
	store := newOutboxTestStore()
	q := &settlementRetryQueue{}
	q.SetOutbox(outboxTestWriter(t, store, nil))
	if q.Enqueue(outboxSettleJob(gateway)) {
		t.Fatal("disabled queue accepted a job")
	}
	if objects := store.parked(t, 1); objects[0].Reason != "queue_disabled" || objects[0].Attempts != 1 {
		t.Fatalf("parked object = %+v", objects[0])
	}
}

func TestShutdownFlushParksWhatIsStillQueued(t *testing.T) {
	gateway, _ := frozenRetryGateway(t, nil)
	store := newOutboxTestStore()
	// Never started: nothing drains the queue, as when the worker is stuck
	// on a slow router at exit.
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4), maxAttempts: 3}
	q.SetOutbox(outboxTestWriter(t, store, nil))
	for i := 1; i <= 3; i++ {
		job := outboxSettleJob(gateway)
		job.usage.OutputTokens = i
		if !q.Enqueue(job) {
			t.Fatal("Enqueue refused")
		}
	}
	expired, cancel := context.WithCancel(t.Context())
	cancel()
	q.Flush(expired)
	objects := store.parked(t, 3)
	for i, object := range objects {
		if object.Reason != "shutdown" || !bytes.Contains(object.Body, []byte(`"actual_output_tokens":`+string(rune('0'+i+1)))) {
			t.Fatalf("object %d = %+v body = %s", i, object, object.Body)
		}
	}
	if len(q.jobs) != 0 {
		t.Fatalf("queued = %d after flush", len(q.jobs))
	}
}

func TestParkSkipsJobsWithNothingToSend(t *testing.T) {
	gateway, _ := frozenRetryGateway(t, nil)
	store := newOutboxTestStore()
	q := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 4)}
	writer := outboxTestWriter(t, store, nil)
	q.SetOutbox(writer)
	// A refund without an authorization freezes to nil: nothing to send.
	q.park(settlementRetryJob{trGateway: gateway, kind: "refund"}, "retry_exhausted")
	// A frozen terminal that could not be built has no bytes to park.
	q.park(settlementRetryJob{trGateway: nil, authorization: frozenRetryPrivateAuthorization(0, true)}, "retry_exhausted")
	if writer.Pending() != 0 {
		t.Fatalf("pending = %d", writer.Pending())
	}
	store.parked(t, 0)
}

func TestPrepareSettleOutboxIsOffWithoutABucketOrAStore(t *testing.T) {
	if plan := prepareSettleOutbox("", func(string) (settleoutbox.Store, error) {
		t.Fatal("store built without a bucket")
		return nil, nil
	}); plan.Configured() {
		t.Fatal("plan built without a bucket")
	}
	if plan := prepareSettleOutbox("bucket", func(string) (settleoutbox.Store, error) {
		return nil, errors.New("unsupported_cloud")
	}); plan.Configured() {
		t.Fatal("plan built without a store")
	}
	if writer := startSettleOutbox(t.Context(), nil, nil); writer != nil {
		t.Fatal("writer started from a nil plan")
	}
	var q *settlementRetryQueue
	q.SetOutbox(nil)
	q.park(settlementRetryJob{}, "retry_exhausted")
}

func TestSettleOutboxBucketComesFromTheEnvironment(t *testing.T) {
	for raw, want := range map[string]string{"": "", "  ": "", "gs://outbox-bucket": "outbox-bucket", " outbox-bucket ": "outbox-bucket"} {
		t.Setenv(settleOutboxBucketEnv, raw)
		if got := settleOutboxBucket(); got != want {
			t.Fatalf("settleOutboxBucket(%q) = %q, want %q", raw, got, want)
		}
	}
}

// The launch policy must allow the bucket override or Confidential Space
// refuses the instance template that sets it.
func TestGCPLaunchPoliciesAllowTheOutboxBucketOverride(t *testing.T) {
	for _, name := range []string{"Dockerfile.enclave.gcp.multi", "Dockerfile.enclave.gcp.anthropic"} {
		raw, err := os.ReadFile("../../" + name)
		if err != nil {
			t.Fatal(err)
		}
		var policy string
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, `LABEL "tee.launch_policy.allow_env_override"=`) {
				policy = line
			}
		}
		if policy == "" {
			t.Fatalf("%s has no launch policy label", name)
		}
		if !strings.Contains(policy, ","+settleOutboxBucketEnv+",") {
			t.Fatalf("%s launch policy does not allow %s", name, settleOutboxBucketEnv)
		}
	}
}

// main must resolve the outbox before the boot declaration that reads it,
// and attach the writer after the receipt signer exists (so parked terminals
// can be boot-signed) and before serving starts (so no retry is lost unparked).
func TestMainStartsTheOutboxAfterTheSignerAndBeforeServing(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var mainFunc *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "main" {
			mainFunc = fn
		}
	}
	if mainFunc == nil {
		t.Fatal("func main not found in main.go")
	}
	positions := map[string][]token.Pos{}
	ast.Inspect(mainFunc.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		switch name {
		case "prepareSettleOutbox", "declareStageDBootCapabilities", "startSettleOutbox", "SetOutbox", "initializeReceiptSignerWithSpendLease", "serveWithShadowV2Startup":
			positions[name] = append(positions[name], call.Pos())
		}
		if name == "startSettleOutbox" {
			// The signer must be the registered boot's key, never the raw
			// receipt signer: an unregistered boot's signature verifies
			// against nothing and would be mistaken for trust.
			signerCall, ok := call.Args[len(call.Args)-1].(*ast.CallExpr)
			var signerName string
			if ok {
				if sel, ok := signerCall.Fun.(*ast.SelectorExpr); ok {
					signerName = sel.Sel.Name
				}
			}
			if signerName != "RegisteredBootSigner" {
				t.Errorf("startSettleOutbox signer argument is not RegisteredBootSigner() at %s", fset.Position(call.Pos()))
			}
		}
		return true
	})
	for _, name := range []string{"prepareSettleOutbox", "declareStageDBootCapabilities", "startSettleOutbox", "SetOutbox", "initializeReceiptSignerWithSpendLease", "serveWithShadowV2Startup"} {
		if len(positions[name]) != 1 {
			t.Fatalf("%s called %d times in main, want 1", name, len(positions[name]))
		}
	}
	line := func(name string) int { return fset.Position(positions[name][0]).Line }
	// The plan is resolved before the declaration (which reads it), the
	// writer starts after the signer and before serving.
	if !(line("prepareSettleOutbox") < line("declareStageDBootCapabilities") && line("initializeReceiptSignerWithSpendLease") < line("startSettleOutbox") && line("startSettleOutbox") < line("SetOutbox") && line("SetOutbox") < line("serveWithShadowV2Startup")) {
		t.Fatalf("order: prepare %d, declare %d, signer %d, start %d, set %d, serve %d", line("prepareSettleOutbox"), line("declareStageDBootCapabilities"), line("initializeReceiptSignerWithSpendLease"), line("startSettleOutbox"), line("SetOutbox"), line("serveWithShadowV2Startup"))
	}
}
