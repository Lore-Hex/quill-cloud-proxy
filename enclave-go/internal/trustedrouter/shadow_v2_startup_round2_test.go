package trustedrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Ordinary serving uses the real request entry with an in-memory router reply.
func startupOrdinaryRequest(t *testing.T) {
	t.Helper()
	c := New("https://trustedrouter.com", "test", &http.Client{Transport: startupRoundTrip(func(*http.Request) (*http.Response, error) {
		return v2Reply(`{"data":{"model":"ordinary"}}`), nil
	})})
	c.asyncShadow = true
	a, err := c.AuthorizeWithRoute(t.Context(), "ordinary-input", &qtypes.OpenAIChatRequest{Model: "ordinary"}, "chat.completions")
	if err != nil || a.Model != "ordinary" {
		t.Fatalf("ordinary response: %v %v", a, err)
	}
}

func startupInstallInputs(t *testing.T, port string, crash bool, release <-chan struct{}) time.Time {
	t.Helper()
	t.Setenv("TR_SHADOW_V2_STARTUP_MANIFEST", "configured-test-input")
	fixture, d, m, writer := startupFixture(t)
	old := configureStartupInputs
	t.Cleanup(func() { configureStartupInputs = old })
	configureStartupInputs = func(h *ShadowV2StartupHarness) {
		h.emitter.close()
		h.emitter, h.now, h.probe, h.image, h.retainReady = fixture.emitter, fixture.now, fixture.probe, fixture.image, fixture.retainReady
		h.acquire = func(context.Context) (startupLaunchAcquisition, error) {
			return startupLaunchAcquisition{descriptor: d}, nil
		}
		h.load = func() (startupManifest, []byte, error) { raw, _ := canonicalShadow(m); return m, raw, nil }
		wait := func() {
			if crash {
				panic("startup input stopped")
			}
			<-release
		}
		switch port {
		case "descriptor":
			h.acquire = func(context.Context) (startupLaunchAcquisition, error) {
				wait()
				return startupLaunchAcquisition{}, errStartupRecord
			}
		case "manifest":
			h.load = func() (startupManifest, []byte, error) { wait(); return m, nil, errStartupRecord }
		case "probe":
			h.probe = func(context.Context, startupTarget) startupProbeResult { wait(); return startupProbeResult{} }
		case "image":
			h.image = func(context.Context) ([]byte, error) { wait(); return nil, errStartupRecord }
		case "ack":
			h.retainReady = func(context.Context, []byte) (string, error) { wait(); return "", errStartupRecord }
		case "coordinator":
			h.now = func() time.Time { wait(); return time.Time{} }
		case "output":
			h.emitter = newStartupEmitter(startupCrashWriter{})
			t.Cleanup(h.emitter.close)
		}
		_ = writer
	}
	return fixture.start
}

type startupCrashWriter struct{}

func (startupCrashWriter) Write([]byte) (int, error) { panic("startup output stopped") }

func TestStartupPanickingPorts(t *testing.T) {
	if port := os.Getenv("STARTUP_PANIC_PORT"); port != "" {
		start := startupInstallInputs(t, port, true, nil)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if port == "launch" {
			ctx = nil
		} // Exercise the outer coordinator before input dispatch.
		h := StartShadowV2Startup(ctx, start, nil, true, nil, &Client{asyncShadow: true}, nil)
		startupOrdinaryRequest(t)
		select {
		case <-h.done:
		case <-time.After(2 * time.Second):
			t.Fatal("coordinator did not finish")
		}
		if EnclaveOptedAdmission() {
			t.Fatal("panicking input made admission available")
		}
		startupOrdinaryRequest(t)
		return
	}
	for _, port := range []string{"manifest", "probe", "image", "ack", "descriptor", "coordinator", "output", "launch"} {
		t.Run(port, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartupPanickingPorts$") //nolint:gosec // Relaunch this test binary with fixed arguments.
			cmd.Env = append(os.Environ(), "STARTUP_PANIC_PORT="+port)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ordinary serving ended: %v\n%s", err, out)
			}
		})
	}
}

func TestStartupProductionHandoff(t *testing.T) {
	for _, port := range []string{"descriptor", "manifest", "probe", "image", "ack"} {
		t.Run(port, func(t *testing.T) {
			release := make(chan struct{})
			start := startupInstallInputs(t, port, false, release)
			ctx, cancel := context.WithCancel(context.Background())
			returned := make(chan *ShadowV2StartupHarness, 1)
			served := make(chan struct{})
			go func() {
				h := StartShadowV2Startup(ctx, start, nil, true, nil, &Client{asyncShadow: true}, nil)
				returned <- h
				defer close(served)
				startupOrdinaryRequest(t)
			}()
			var h *ShadowV2StartupHarness
			select {
			case h = <-returned:
			case <-time.After(500 * time.Millisecond):
				t.Error("StartShadowV2Startup delayed serving")
			}
			if h != nil {
				select {
				case <-served:
				case <-time.After(500 * time.Millisecond):
					t.Error("ordinary request delayed")
				}
				if EnclaveOptedAdmission() {
					t.Error("hung input made admission available")
				}
			}
			cancel()
			close(release)
			if h == nil {
				select {
				case h = <-returned:
				case <-time.After(time.Second):
					t.Fatal("startup did not return after release")
				}
			}
			<-h.done
			<-served
		})
	}
}

func TestStartupAdmissionBoundary(t *testing.T) {
	h, _, _, _ := startupFixture(t)
	h.now = func() time.Time { panic("retention sampled startup clock") }
	for _, ready := range []bool{false, true} {
		enclaveOptedAdmission.Store(&startupAdmission{ready: ready, harness: h})
		if allocs := testing.AllocsPerRun(100, func() { EnclaveOptedAdmission() }); allocs != 0 {
			t.Fatalf("hook allocations %g", allocs)
		}
	}
	h.mu.Lock()
	h.attemptMu.Lock()
	defer h.mu.Unlock()
	defer h.attemptMu.Unlock()
	c := &Client{asyncShadow: true}
	for _, ready := range []bool{false, true} {
		enclaveOptedAdmission.Store(&startupAdmission{ready: ready, harness: h})
		a := v2Authorization(t, shadowV2Variants(t, "authorize_compared")[0])
		done := make(chan struct{})
		go func() { c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions"); close(done) }()
		select {
		case <-done:
		case <-time.After(250 * time.Millisecond):
			t.Fatal("request waited for startup recorder")
		}
	}
	if h.attemptOverflow.Load() != 0 {
		t.Fatal("retention decision reached recorder")
	}
	for _, on := range []bool{false, true} {
		c.asyncShadow = on
		a := &Authorization{}
		req := &qtypes.OpenAIChatRequest{}
		enclaveOptedAdmission.Store(nil)
		if allocs := testing.AllocsPerRun(100, func() { c.recordStartupAdmissionStart(a, "chat.completions") }); allocs != 0 {
			t.Fatalf("ordinary startup recorder allocations %g", allocs)
		}
		baseline := testing.AllocsPerRun(100, func() { c.retainShadowAuthorization(a, req, "messages") })
		enclaveOptedAdmission.Store(&startupAdmission{harness: h})
		got := testing.AllocsPerRun(100, func() { c.retainShadowAuthorization(a, req, "messages") })
		if got != baseline {
			t.Fatalf("ordinary retention allocations %g, base %g", got, baseline)
		}
	}
}

func TestStartupNonOptedBothStates(t *testing.T) {
	h, _, _, _ := startupFixture(t)
	enclaveOptedAdmission.Store(nil)
	_, baseline := shadowAuth(t)
	for _, ready := range []bool{false, true} {
		t.Run(fmt.Sprint(ready), func(t *testing.T) {
			enclaveOptedAdmission.Store(&startupAdmission{ready: ready, harness: h})
			_, actual := shadowAuth(t)
			if !reflect.DeepEqual(actual, baseline) {
				t.Fatal("full v1 retained outcome changed")
			}
			t.Run("transcript", TestStartupNonOptedTranscript)
			t.Run("frozen-main", TestAsyncLiveFrozenMain)
			t.Run("old-router", TestShadowV2OldRouterOracle)
			t.Run("legacy-body", TestShadowV2LegacyBodyLiteral)
		})
	}
	if len(h.attempts) != 0 || h.attemptOverflow.Load() != 0 {
		t.Fatal("non-opted request recorded")
	}
}

func TestStartupIncomingValuesBothStates(t *testing.T) {
	h, d, m, w := startupFixture(t)
	var incoming []string
	request := func(ready bool) {
		for _, route := range []string{"chat.completions", "responses"} {
			for _, variant := range []string{"authorize_compared", "authorize_excluded"} {
				prefix := fmt.Sprintf("incoming-%v-%s-%s-", ready, route, variant)
				a := v2Authorization(t, shadowV2Variants(t, variant)[0])
				a.AuthorizationID = prefix + "authorization"
				a.WorkspaceID = prefix + "workspace"
				a.GenerationID = prefix + "generation"
				req := &qtypes.OpenAIChatRequest{IdempotencyKey: prefix + "idempotency", Model: prefix + "model", Metadata: map[string]any{"incoming": prefix + "metadata"}}
				incoming = append(incoming, a.AuthorizationID, a.WorkspaceID, a.GenerationID, req.IdempotencyKey, req.Model, prefix+"metadata")
				(&Client{asyncShadow: true}).retainShadowAuthorization(a, req, route)
			}
		}
	}
	enclaveOptedAdmission.Store(&startupAdmission{harness: h})
	request(false)
	runStartupFixture(h, d, m)
	if !EnclaveOptedAdmission() {
		t.Fatal("ready path not exercised")
	}
	request(true)
	// Exercise the two constructors whose originals are not yet supplied by the
	// installed ports, through the same writer as the production constructors.
	all := startupAllRecords(t)
	for _, r := range all {
		switch r.(type) {
		case startupAttempt, startupShutdown:
			if _, ok := h.emitter.emit(r); !ok {
				t.Fatal("record emission")
			}
		}
	}
	var capture bytes.Buffer
	w.mu.Lock()
	capture.Write(w.Bytes())
	w.mu.Unlock()
	capture.Write(h.manifestOriginal)
	capture.Write(h.configOriginal)
	capture.Write(h.readyOriginal)
	for _, o := range h.originals {
		capture.Write(o.raw)
	}
	for _, value := range incoming {
		if bytes.Contains(capture.Bytes(), []byte(value)) {
			t.Fatalf("incoming value entered records: %s", value)
		}
	}
	if len(w.records(t)) != 10 {
		t.Fatalf("unexpected record population: %d", len(w.records(t)))
	}
}

func TestStartupAttemptResults(t *testing.T) {
	var inv struct {
		Results []string `json:"attempt_results"`
	}
	raw, err := os.ReadFile("testdata/shadow_v2_runtime_records_inventory.json")
	if err != nil || json.Unmarshal(raw, &inv) != nil {
		t.Fatal("inventory")
	}
	w := &startupTestWriter{}
	e := newStartupEmitter(w)
	defer e.close()
	r := startupAttempt{"a3_opted_attempt", "boot", 1, "", startupReceipt{"2026-10-13", "boot", 1, startupCoordinate{"receipt_page", strings.Repeat("a", 64), 1}}}
	for _, result := range inv.Results {
		r.Result = result
		if _, ok := e.emit(r); !ok {
			t.Fatalf("allowed result %s dropped", result)
		}
	}
	for _, result := range []string{"other", "", "Accepted", "pass", "failed ", "incoming-value"} {
		r.Result = result
		if _, ok := e.emit(r); ok {
			t.Fatalf("outside result %q emitted", result)
		}
	}
	if e.dropped.Load() != 6 || len(w.records(t)) != len(inv.Results) {
		t.Fatal("result output or drop count")
	}
}

func TestStartupUnknownCoordinates(t *testing.T) {
	for _, kind := range []string{"unlisted_original", "", "future_kind"} {
		if _, ok := retainStartupOriginal(kind, []byte("x")); ok {
			t.Fatal("unknown original retained")
		}
		e := newStartupEmitter(io.Discard)
		r := startupAttempt{"a3_opted_attempt", "boot", 1, "rejected", startupReceipt{"2026-10-13", "boot", 1, startupCoordinate{kind, strings.Repeat("a", 64), 1}}}
		if _, ok := e.emit(r); ok || e.dropped.Load() != 1 {
			t.Fatal("unknown original emitted")
		}
		e.close()
	}
}

// Bound every string by its field rule and every number by the longest int64.
// Dependencies have the largest permitted population. This deliberately loose
// upper bound still proves that the outer production ceilings are unreachable.
func startupShapeUpperBound(t *testing.T, record any) int {
	t.Helper()
	if r, ok := record.(startupTransportCheck); ok {
		dep := r.Dependencies[0]
		r.Dependencies = nil
		for i := 0; i < 16; i++ {
			d := dep
			d.Resource = fmt.Sprintf("resource-%d", i)
			r.Dependencies = append(r.Dependencies, d)
		}
		record = r
	}
	raw, err := canonicalShadow(record)
	if err != nil {
		t.Fatal(err)
	}
	var tree any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&tree) != nil {
		t.Fatal("shape decode")
	}
	extra := 0
	var walk func(any, string)
	walk = func(v any, key string) {
		switch x := v.(type) {
		case map[string]any:
			for k, value := range x {
				walk(value, k)
			}
		case []any:
			for _, value := range x {
				walk(value, key)
			}
		case json.Number:
			extra += 19 - len(x.String())
		case bool:
			if x {
				extra++
			}
		case string:
			max := 128
			switch key {
			case "revision", "source_revision", "attested_revision":
				max = 40
			case "config_sha256", "policy_sha256", "fixture_sha256", "sha256":
				max = 64
			case "day":
				max = 10
			case "kind", "role", "criterion", "clock":
				max = len(x)
			case "operation":
				max = 9
			case "result":
				max = 8
			case "outcome":
				max = 9
			case "TR_ASYNC_SETTLE_SHADOW", "TR_ASYNC_SETTLE_NEGOTIATE":
				max = 5
			}
			// Check names map only to pass/fail, never to arbitrary identifiers.
			for _, names := range startupChecks {
				for _, name := range strings.Fields(names) {
					if key == name {
						max = 4
					}
				}
			}
			extra += max - len(x)
		}
	}
	walk(tree, "")
	return len(raw) + extra
}

func TestStartupEmissionByteBoundary(t *testing.T) {
	for _, record := range startupAllRecords(t) {
		t.Run(reflect.TypeOf(record).Name(), func(t *testing.T) {
			raw, err := startupRecordBytes(record)
			if err != nil {
				t.Fatal(err)
			}
			var head struct {
				Kind string `json:"kind"`
			}
			if json.Unmarshal(raw, &head) != nil {
				t.Fatal("kind")
			}
			ceiling := startupLimits[head.Kind]
			upper := startupShapeUpperBound(t, record)
			if upper >= ceiling {
				t.Fatalf("shape requires a production-ceiling case: upper=%d ceiling=%d", upper, ceiling)
			}
			t.Logf("field/count upper bound %d < production ceiling %d; exercise emission with ceiling set to serialized length", upper, ceiling)
			// Since no valid shape reaches the production ceiling, use that same table
			// at the exact serialized size and one byte below it. No helper-only call.
			defer func() { startupLimits[head.Kind] = ceiling }()
			w := &startupTestWriter{}
			e := newStartupEmitter(w)
			defer e.close()
			startupLimits[head.Kind] = len(raw)
			emitted, ok := e.emit(record)
			if !ok || !bytes.Equal(emitted, raw) {
				t.Fatal("at-limit output missing")
			}
			startupLimits[head.Kind] = len(raw) - 1
			if _, ok = e.emit(record); ok {
				t.Fatal("one-over output accepted")
			}
			w.mu.Lock()
			defer w.mu.Unlock()
			if !bytes.Equal(w.Bytes(), append(bytes.Clone(raw), '\n')) || e.dropped.Load() != 1 {
				t.Fatal("emitted bytes or drop count changed")
			}
		})
	}
}

func TestStartupSharedReleaseOriginal(t *testing.T) {
	h, d, m, w := startupFixture(t)
	raw, err := os.ReadFile("testdata/shadow_v2_shared_release_config.json")
	if err != nil {
		t.Fatal(err)
	}
	// The literal is intentionally formatted and has shared fields beyond the
	// local projection. Neither formatting nor those fields may be discarded.
	m.ConfigOriginal = string(raw)
	sum := sha256.Sum256(raw)
	m.ConfigSHA256 = hex.EncodeToString(sum[:])
	m.PublicDescriptors.ConfigSHA256 = m.ConfigSHA256
	for _, sources := range m.Artifacts {
		for key, a := range sources {
			a.ConfigSHA256 = m.ConfigSHA256
			sources[key] = a
		}
	}
	if !m.valid(d) {
		t.Fatal("shared original rejected")
	}
	runStartupFixture(h, d, m)
	if !bytes.Equal(h.configOriginal, raw) {
		t.Fatal("shared original changed")
	}
	rows := w.records(t)
	if recordKinds(rows, "a3_boot_check") != 6 {
		t.Fatal("six adoptions missing")
	}
	for _, row := range rows {
		if row["kind"] == "a3_boot_check" && row["config_sha256"] != m.ConfigSHA256 {
			t.Fatal("collector config join differs")
		}
	}
	if len(h.observedDependencies) != 2 {
		t.Fatal("router dependency selected locally")
	}
	for _, dep := range h.observedDependencies {
		if dep.Resource != "router.example" || dep.DeadlineUS != 10000000 {
			t.Fatal("local target/deadline")
		}
	}
	if out := os.Getenv("STARTUP_COLLECTOR_OUTPUT"); out != "" {
		originals := map[string]json.RawMessage{}
		for _, original := range h.originals {
			originals[original.coordinate.SHA256] = original.raw
		}
		payload := map[string]any{"records": rows, "originals": originals, "config_original": m.ConfigOriginal, "manifest": m}
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(out, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Same parsed object, different exact original: the old digest must fail.
	m.ConfigOriginal = string(bytes.TrimSpace(raw))
	if m.valid(d) {
		t.Fatal("different original accepted with old digest")
	}
}

func TestStartupRealRequestRecorder(t *testing.T) {
	h, _, _, _ := startupFixture(t)
	h.mu.Lock()
	h.attemptMu.Lock()
	defer h.mu.Unlock()
	defer h.attemptMu.Unlock()
	for _, ready := range []bool{false, true} {
		enclaveOptedAdmission.Store(&startupAdmission{ready: ready, harness: h})
		raw := shadowV2Variants(t, "authorize_compared")[0]["object"]
		c := New("https://trustedrouter.com", "test", &http.Client{Transport: startupRoundTrip(func(*http.Request) (*http.Response, error) { return v2Reply(`{"data":` + string(raw) + `}`), nil })})
		c.asyncShadow = true
		done := make(chan error, 1)
		go func() {
			_, err := c.AuthorizeWithRoute(t.Context(), "incoming-request", &qtypes.OpenAIChatRequest{Model: "fixture"}, "chat.completions")
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("request entry waited for recorder")
		}
	}
	if h.attemptOverflow.Load() != 2 {
		t.Fatal("request entry did not account for busy recorder")
	}
	for _, on := range []bool{false, true} {
		t.Run(fmt.Sprint(on), func(t *testing.T) {
			c := New("https://trustedrouter.com", "test", &http.Client{Transport: startupRoundTrip(func(*http.Request) (*http.Response, error) {
				return v2Reply(`{"data":{"model":"ordinary","invocation_nonce":"fixed"}}`), nil
			})})
			c.asyncShadow = on
			req := &qtypes.OpenAIChatRequest{Model: "ordinary", IdempotencyKey: "ordinary-id"}
			inv := &authorizationInvocation{nonce: "fixed"}
			inv.once.Do(func() {})
			ctx := context.WithValue(t.Context(), authorizationInvocationContextKey{}, inv)
			run := func() {
				clear(inv.claimed)
				if _, err := c.AuthorizeWithRoute(ctx, "ordinary", req, "messages"); err != nil {
					panic(err)
				}
			}
			enclaveOptedAdmission.Store(nil)
			before := testing.AllocsPerRun(100, run)
			enclaveOptedAdmission.Store(&startupAdmission{harness: h})
			got := testing.AllocsPerRun(100, run)
			enclaveOptedAdmission.Store(nil)
			after := testing.AllocsPerRun(100, run)
			t.Logf("real request allocations: baseline %g..%g, installed %g", min(before, after), max(before, after), got)
			// The complete request includes maps whose bucket allocation varies
			// with the runtime seed. Use the existing live oracle's 16-allocation
			// classes here; hook and ordinary recorder checks above require zero.
			class := func(v float64) int { return (int(v) + 15) / 16 }
			if class(got) != class(max(before, after)) {
				t.Fatalf("real request allocation class differs: %g vs baseline %g", got, max(before, after))
			}

		})
	}
}

func TestStartupRecorderPolicySpellings(t *testing.T) {
	h, _, _, _ := startupFixture(t)
	enclaveOptedAdmission.Store(&startupAdmission{harness: h})
	c := &Client{asyncShadow: true}
	for _, raw := range []string{`"shadow-v2"`, `"\u0073hadow-v2"`, `"shadow\u002Dv2"`, " \t\r\n\"shadow-v2\" ", `null`, `123`, `"other"`, `"shadow-v2 "`, `"shadow-v2" "extra"`, `"shadow\u000Dv2"`, "\u00a0\"shadow-v2\""} {
		var decoded string
		want := json.Unmarshal([]byte(raw), &decoded) == nil && decoded == shadowPolicyV2
		if startupOptedPolicy([]byte(raw)) != want {
			t.Fatalf("marker spelling %q", raw)
		}
		a := &Authorization{BillingShadowPolicy: json.RawMessage(raw)}
		if allocs := testing.AllocsPerRun(100, func() { c.recordStartupAdmissionStart(a, "chat.completions") }); allocs != 0 {
			t.Fatalf("recorder allocated for %q: %g", raw, allocs)
		}
	}
}
