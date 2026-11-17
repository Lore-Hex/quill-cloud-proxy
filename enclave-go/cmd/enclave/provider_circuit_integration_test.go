package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

type providerCircuitTestClock struct{ nanos atomic.Int64 }

func newProviderCircuitTestClock() *providerCircuitTestClock {
	clock := &providerCircuitTestClock{}
	clock.nanos.Store(time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC).UnixNano())
	return clock
}

func (c *providerCircuitTestClock) Now() time.Time          { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *providerCircuitTestClock) Advance(d time.Duration) { c.nanos.Add(int64(d)) }

// resetProviderCircuitsForTest gives a test a clean process-wide breaker with
// the production defaults (threshold 3, 60 s open, 30 s route memory) on the
// given clock. Package tests share one process, and each test's scripted
// provider failures describe its own world, not the next test's.
func resetProviderCircuitsForTest(t *testing.T, now func() time.Time) {
	t.Helper()
	registry := providerCircuits
	reset := func(clock func() time.Time) {
		registry.mu.Lock()
		registry.enabled = true
		registry.threshold = 3
		registry.openFor = time.Minute
		registry.now = clock
		registry.states = map[string]providerCircuitState{}
		registry.routes = map[string]providerRouteMemory{}
		registry.mu.Unlock()
	}
	reset(now)
	t.Cleanup(func() { reset(time.Now) })
}

// enableProviderCircuitsForTest resets the breaker onto a controllable clock
// and makes same-provider retry backoff instant.
func enableProviderCircuitsForTest(t *testing.T) *providerCircuitTestClock {
	t.Helper()
	t.Setenv("QUILL_KEEPALIVE", "off")
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	clock := newProviderCircuitTestClock()
	resetProviderCircuitsForTest(t, clock.Now)
	oldSleep := sleepBeforeTransientRetry
	sleepBeforeTransientRetry = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	t.Cleanup(func() { sleepBeforeTransientRetry = oldSleep })
	return clock
}

type providerCircuitTestCandidate struct {
	provider string
	endpoint string
}

// providerCircuitControlPlane is a fake control plane that counts the billing
// calls the breaker exists to avoid. Each credential is its own workspace.
type providerCircuitControlPlane struct {
	server     *httptest.Server
	gateway    *trustedrouter.Client
	authorizes atomic.Int32
	refunds    atomic.Int32
	settles    atomic.Int32
	mu         sync.Mutex
	settled    []map[string]any
}

func newProviderCircuitControlPlane(t *testing.T, model string, candidates ...providerCircuitTestCandidate) *providerCircuitControlPlane {
	t.Helper()
	plane := &providerCircuitControlPlane{}
	routeCandidates := make([]map[string]any, 0, len(candidates))
	for _, candidate := range candidates {
		routeCandidates = append(routeCandidates, map[string]any{
			"endpoint_id": candidate.endpoint, "model": model, "upstream_model": model,
			"provider": candidate.provider, "provider_name": candidate.provider, "usage_type": "Credits",
		})
	}
	plane.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		credential, _ := body["api_key_lookup_hash"].(string)
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			n := plane.authorizes.Add(1)
			encoded, _ := json.Marshal(map[string]any{"data": map[string]any{
				"authorization_id": fmt.Sprintf("auth_circuit_%d", n),
				"workspace_id":     "ws_" + credential[:min(12, len(credential))], "api_key_hash": "key_" + credential[:min(12, len(credential))],
				"model": model, "upstream_model": model, "requested_model": model,
				"endpoint_id": candidates[0].endpoint, "provider": candidates[0].provider,
				"usage_type": "Credits", "limit_usage_type": "Credits",
				"route_candidates": routeCandidates,
			}})
			_, _ = w.Write(encoded)
		case "/internal/gateway/refund":
			plane.refunds.Add(1)
			_, _ = io.WriteString(w, `{"data":{"refunded":true}}`)
		case "/internal/gateway/settle":
			plane.settles.Add(1)
			plane.mu.Lock()
			plane.settled = append(plane.settled, body)
			plane.mu.Unlock()
			_, _ = io.WriteString(w, `{"data":{"settled":true,"generation_id":"gen_circuit","cost_microdollars":1}}`)
		default:
			_, _ = io.WriteString(w, `{"data":{"workspace_id":"ws_circuit","api_key_hash":"key_circuit"}}`)
		}
	}))
	t.Cleanup(plane.server.Close)
	plane.gateway = trustedrouter.New(plane.server.URL, "internal-test", plane.server.Client())
	return plane
}

func (p *providerCircuitControlPlane) counts() (authorizes, refunds, settles int32) {
	return p.authorizes.Load(), p.refunds.Load(), p.settles.Load()
}

// providerCircuitTestUpstream fails per provider as scripted, optionally
// holds calls at a gate, and records every upstream call it receives.
type providerCircuitTestUpstream struct {
	mu      sync.Mutex
	calls   []string
	fail    map[string]error
	gate    chan struct{}
	entered chan struct{}
	partial bool
}

func (u *providerCircuitTestUpstream) InvokeStreaming(
	_ context.Context,
	_ *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	options ...llm.InvokeOptions,
) error {
	option := llm.InvokeOptions{}
	if len(options) > 0 {
		option = options[0]
	}
	u.mu.Lock()
	u.calls = append(u.calls, option.Provider)
	err := u.fail[option.Provider]
	gate, entered, partial := u.gate, u.entered, u.partial
	u.gate, u.entered = nil, nil
	u.mu.Unlock()
	if err != nil {
		return err
	}
	if gate != nil {
		split := 0
		if partial {
			// Accepted: output is already flowing when the call is held.
			split = strings.Index(providerStreamTestResponse, "event: content_block_delta")
			if _, writeErr := io.WriteString(out, providerStreamTestResponse[:split]); writeErr != nil {
				return writeErr
			}
		}
		close(entered)
		<-gate
		_, err = io.WriteString(out, providerStreamTestResponse[split:])
		return err
	}
	_, err = io.WriteString(out, providerStreamTestResponse)
	return err
}

// holdNextCall makes the next call wait until the returned release is
// called; entered closes once that call is in progress.
func (u *providerCircuitTestUpstream) holdNextCall(partial bool) (entered <-chan struct{}, release func()) {
	u.mu.Lock()
	defer u.mu.Unlock()
	gate, in := make(chan struct{}), make(chan struct{})
	u.gate, u.entered, u.partial = gate, in, partial
	var once sync.Once
	return in, func() { once.Do(func() { close(gate) }) }
}

func (u *providerCircuitTestUpstream) setFailure(provider string, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.fail == nil {
		u.fail = map[string]error{}
	}
	if err == nil {
		delete(u.fail, provider)
		return
	}
	u.fail[provider] = err
}

func (u *providerCircuitTestUpstream) callsTo(provider string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, call := range u.calls {
		if call == provider {
			n++
		}
	}
	return n
}

func (u *providerCircuitTestUpstream) total() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.calls)
}

func providerCircuitUpstreamStatus(status int) error {
	return &upstreamerror.Error{Status: status, Body: fmt.Sprintf(`{"error":{"message":"upstream status %d"}}`, status)}
}

func serveProviderCircuitRequest(
	t *testing.T,
	plane *providerCircuitControlPlane,
	upstream llm.Client,
	bearer, path, body string,
) (*http.Response, []byte) {
	t.Helper()
	raw := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		path, bearer, len(body), body,
	)
	conn := newScriptedConn(raw, nil)
	captureStderr(t, func() {
		serveOne(context.Background(), conn, auth.New(nil), upstream, nil, nil, plane.gateway, nil)
	})
	return readRawHTTPResponse(t, conn.writes.Bytes())
}

func bufioReader(raw []byte) *bufio.Reader { return bufio.NewReader(bytes.NewReader(raw)) }

func chatBodyForCircuit(model string, stream bool) string {
	return fmt.Sprintf(`{"model":%q,"stream":%t,"messages":[{"role":"user","content":"hello"}]}`, model, stream)
}

func assertProviderCircuitRefusal(t *testing.T, step string, response *http.Response, body []byte, wantRetryAfter string) {
	t.Helper()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("%s: status=%d body=%s, want 503", step, response.StatusCode, body)
	}
	if got := response.Header.Get("Retry-After"); got != wantRetryAfter {
		t.Fatalf("%s: Retry-After=%q, want %q", step, got, wantRetryAfter)
	}
	if got := response.Header.Get("X-Should-Retry"); got != "true" {
		t.Fatalf("%s: x-should-retry=%q, want true", step, got)
	}
}

func assertNotProviderCircuitRefusal(t *testing.T, step string, response *http.Response, body []byte) {
	t.Helper()
	if response.Header.Get("Retry-After") != "" || strings.Contains(string(body), "temporarily unavailable") {
		t.Fatalf("%s: unexpected circuit refusal: status=%d body=%s", step, response.StatusCode, body)
	}
}

// openSharedCircuit fails one request from each of three tenants.
func openSharedCircuit(t *testing.T, plane *providerCircuitControlPlane, upstream llm.Client, model, prefix string) {
	t.Helper()
	for _, tenant := range []string{"a", "b", "c"} {
		response, body := serveProviderCircuitRequest(t, plane, upstream, prefix+"-"+tenant, "/v1/chat/completions", chatBodyForCircuit(model, false))
		assertNotProviderCircuitRefusal(t, "opening tenant "+tenant, response, body)
	}
}

func TestProviderCircuitHammeringTenantFailsFastWithoutAffectingOthers(t *testing.T) {
	clock := enableProviderCircuitsForTest(t)
	const model = "circuit-solo/glm-5.3-flash"
	const provider = "circuit-solo"
	plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, "circuit-solo/glm-5.3-flash@circuit-solo/prepaid"})
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure(provider, providerCircuitUpstreamStatus(502))
	const hammer = "circuit-solo-hammer"

	// Three failed requests (each tries the provider three times) open the
	// hammering tenant's own circuit. Each one is authorized and refunded.
	for i := 1; i <= 3; i++ {
		response, body := serveProviderCircuitRequest(t, plane, upstream, hammer, "/v1/chat/completions", chatBodyForCircuit(model, false))
		if response.StatusCode != http.StatusBadGateway {
			t.Fatalf("failure %d: status=%d body=%s, want relayed 502", i, response.StatusCode, body)
		}
		assertNotProviderCircuitRefusal(t, fmt.Sprintf("failure %d", i), response, body)
	}
	if authorizes, refunds, _ := plane.counts(); authorizes != 3 || refunds != 3 || upstream.total() != 9 {
		t.Fatalf("after opening: authorizes=%d refunds=%d upstream=%d, want 3/3/9", authorizes, refunds, upstream.total())
	}

	// The hammering tenant is refused before authorize: no hold, no refund,
	// no upstream call, and told when to come back.
	response, body := serveProviderCircuitRequest(t, plane, upstream, hammer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	assertProviderCircuitRefusal(t, "hammer fast fail", response, body, "60")
	if authorizes, refunds, _ := plane.counts(); authorizes != 3 || refunds != 3 || upstream.total() != 9 {
		t.Fatalf("hammer fast fail reached billing or the provider: authorizes=%d refunds=%d upstream=%d", authorizes, refunds, upstream.total())
	}

	// Another tenant is not refused: its request reaches the provider.
	response, body = serveProviderCircuitRequest(t, plane, upstream, "circuit-solo-other", "/v1/chat/completions", chatBodyForCircuit(model, false))
	assertNotProviderCircuitRefusal(t, "other tenant", response, body)
	if upstream.total() != 12 {
		t.Fatalf("one tenant's failures refused another tenant: upstream calls=%d, want 12", upstream.total())
	}

	// After the hammer's 30 s route memory expires (still inside its window)
	// it is authorized, not sent upstream, refunded, and told the time left.
	clock.Advance(45 * time.Second)
	authorizesBefore, refundsBefore, _ := plane.counts()
	response, body = serveProviderCircuitRequest(t, plane, upstream, hammer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	assertProviderCircuitRefusal(t, "after route memory expiry", response, body, "15")
	if authorizes, refunds, _ := plane.counts(); authorizes != authorizesBefore+1 || refunds != refundsBefore+1 || upstream.total() != 12 {
		t.Fatalf("after route memory expiry: authorizes=%d refunds=%d upstream=%d", authorizes, refunds, upstream.total())
	}
	response, body = serveProviderCircuitRequest(t, plane, upstream, hammer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	assertProviderCircuitRefusal(t, "refreshed fast fail", response, body, "15")
	if authorizes, _, _ := plane.counts(); authorizes != authorizesBefore+1 {
		t.Fatalf("refreshed fast fail authorized: authorizes=%d", authorizes)
	}

	// After the window one probe goes through, succeeds and closes it.
	clock.Advance(16 * time.Second)
	upstream.setFailure(provider, nil)
	for i := 0; i < 2; i++ {
		response, body = serveProviderCircuitRequest(t, plane, upstream, hammer, "/v1/chat/completions", chatBodyForCircuit(model, false))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("after window %d: status=%d body=%s, want 200", i, response.StatusCode, body)
		}
	}
	if upstream.total() != 14 {
		t.Fatalf("after close: upstream calls=%d, want 14", upstream.total())
	}
}

func TestProviderCircuitThreeTenantsOpenTheSharedCircuit(t *testing.T) {
	enableProviderCircuitsForTest(t)
	const model = "circuit-fresh/glm-5.3-flash"
	const provider = "circuit-fresh"
	plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, "circuit-fresh/glm-5.3-flash@circuit-fresh/prepaid"})
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure(provider, providerCircuitUpstreamStatus(503))
	openSharedCircuit(t, plane, upstream, model, "circuit-fresh")
	before := upstream.total()

	// A new tenant with no remembered route is authorized (its candidates
	// are not known yet), but the open circuit is not called and the
	// streaming client still gets the 503 with Retry-After before any head.
	response, body := serveProviderCircuitRequest(t, plane, upstream, "circuit-fresh-new", "/v1/chat/completions", chatBodyForCircuit(model, true))
	assertProviderCircuitRefusal(t, "new tenant", response, body, "60")
	if authorizes, refunds, _ := plane.counts(); authorizes != 4 || refunds != 4 || upstream.total() != before {
		t.Fatalf("new tenant: authorizes=%d refunds=%d upstream=%d->%d", authorizes, refunds, before, upstream.total())
	}
	// Its next request is refused before authorize.
	response, body = serveProviderCircuitRequest(t, plane, upstream, "circuit-fresh-new", "/v1/chat/completions", chatBodyForCircuit(model, true))
	assertProviderCircuitRefusal(t, "new tenant repeat", response, body, "60")
	if authorizes, refunds, _ := plane.counts(); authorizes != 4 || refunds != 4 {
		t.Fatalf("new tenant repeat: authorizes=%d refunds=%d, want 4/4", authorizes, refunds)
	}
}

func TestProviderCircuitFailedProbeReopensAfterOneCall(t *testing.T) {
	clock := enableProviderCircuitsForTest(t)
	const model = "circuit-probe/glm-5.3-flash"
	const provider = "circuit-probe"
	plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, "circuit-probe/glm-5.3-flash@circuit-probe/prepaid"})
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure(provider, providerCircuitUpstreamStatus(502))
	const bearer = "circuit-probe-key" //nolint:gosec // deterministic public test fixture, not a credential
	for i := 0; i < 3; i++ {
		serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	}
	clock.Advance(61 * time.Second)
	before := upstream.total()

	// Half-open: the probe is authorized and tried once, without the
	// same-provider retry schedule, and its failure reopens the circuit.
	response, body := serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("probe: status=%d body=%s, want relayed 502", response.StatusCode, body)
	}
	if got := upstream.total() - before; got != 1 {
		t.Fatalf("probe made %d upstream calls, want 1", got)
	}
	response, body = serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	assertProviderCircuitRefusal(t, "reopened", response, body, "60")
	if authorizes, refunds, _ := plane.counts(); authorizes != 4 || refunds != 4 {
		t.Fatalf("reopened: authorizes=%d refunds=%d, want 4/4", authorizes, refunds)
	}
}

func TestProviderCircuitHalfOpenAdmitsOneProbeAtATime(t *testing.T) {
	clock := enableProviderCircuitsForTest(t)
	const model = "circuit-gate/glm-5.3-flash"
	const provider = "circuit-gate"
	plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, "circuit-gate/glm-5.3-flash@circuit-gate/prepaid"})
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure(provider, providerCircuitUpstreamStatus(503))
	openSharedCircuit(t, plane, upstream, model, "circuit-gate")
	clock.Advance(61 * time.Second)
	upstream.setFailure(provider, nil)

	entered, release := upstream.holdNextCall(false)
	defer release()
	probeDone := make(chan *http.Response, 1)
	go func() {
		raw := fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer circuit-gate-probe\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(chatBodyForCircuit(model, false)), chatBodyForCircuit(model, false))
		conn := newScriptedConn(raw, nil)
		serveOne(context.Background(), conn, auth.New(nil), upstream, nil, nil, plane.gateway, nil)
		response, _ := http.ReadResponse(bufioReader(conn.writes.Bytes()), nil)
		probeDone <- response
	}()
	<-entered
	before := upstream.total()

	// While the probe is in flight every other attempt is refused.
	response, body := serveProviderCircuitRequest(t, plane, upstream, "circuit-gate-waiter", "/v1/chat/completions", chatBodyForCircuit(model, false))
	assertProviderCircuitRefusal(t, "during probe", response, body, "1")
	if upstream.total() != before {
		t.Fatalf("a second attempt reached the provider during the probe: calls %d->%d", before, upstream.total())
	}

	release()
	if probe := <-probeDone; probe == nil || probe.StatusCode != http.StatusOK {
		t.Fatalf("probe response = %v, want 200", probe)
	}
	response, body = serveProviderCircuitRequest(t, plane, upstream, "circuit-gate-waiter", "/v1/chat/completions", chatBodyForCircuit(model, false))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("after a successful probe: status=%d body=%s, want 200", response.StatusCode, body)
	}
}

func TestProviderCircuitStreamStartedBeforeTheOutageDoesNotCloseIt(t *testing.T) {
	clock := enableProviderCircuitsForTest(t)
	const model = "circuit-stale/glm-5.3-flash"
	const provider = "circuit-stale"
	plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, "circuit-stale/glm-5.3-flash@circuit-stale/prepaid"})
	upstream := &providerCircuitTestUpstream{}

	// A request whose response is already flowing when the outage starts.
	entered, release := upstream.holdNextCall(true)
	defer release()
	longDone := make(chan int, 1)
	go func() {
		raw := fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer circuit-stale-long\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(chatBodyForCircuit(model, false)), chatBodyForCircuit(model, false))
		conn := newScriptedConn(raw, nil)
		serveOne(context.Background(), conn, auth.New(nil), upstream, nil, nil, plane.gateway, nil)
		response, err := http.ReadResponse(bufioReader(conn.writes.Bytes()), nil)
		if err != nil {
			longDone <- 0
			return
		}
		longDone <- response.StatusCode
	}()
	<-entered
	clock.Advance(time.Second)
	upstream.setFailure(provider, providerCircuitUpstreamStatus(502))
	openSharedCircuit(t, plane, upstream, model, "circuit-stale")

	// It completes during the outage: that must not close the circuit.
	release()
	if status := <-longDone; status != http.StatusOK {
		t.Fatalf("long request status=%d, want 200", status)
	}
	before := upstream.total()
	response, body := serveProviderCircuitRequest(t, plane, upstream, "circuit-stale-next", "/v1/chat/completions", chatBodyForCircuit(model, false))
	assertProviderCircuitRefusal(t, "after the old stream", response, body, "60")
	if upstream.total() != before {
		t.Fatal("an old stream's success closed the circuit")
	}
}

func TestProviderCircuitIgnoresClientAndAmbiguousErrors(t *testing.T) {
	for _, status := range []int{400, 401, 404, 422, 429, 500} {
		t.Run(fmt.Sprintf("status=%d", status), func(t *testing.T) {
			enableProviderCircuitsForTest(t)
			provider := fmt.Sprintf("circuit-status-%d", status)
			model := provider + "/glm-5.3-flash"
			plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, model + "@" + provider + "/prepaid"})
			upstream := &providerCircuitTestUpstream{}
			upstream.setFailure(provider, providerCircuitUpstreamStatus(status))
			for i := 1; i <= 5; i++ {
				response, body := serveProviderCircuitRequest(t, plane, upstream, provider+"-key", "/v1/chat/completions", chatBodyForCircuit(model, false))
				if response.StatusCode != status {
					t.Fatalf("request %d: status=%d body=%s, want relayed %d", i, response.StatusCode, body, status)
				}
				assertNotProviderCircuitRefusal(t, fmt.Sprintf("request %d", i), response, body)
			}
			if authorizes, refunds, _ := plane.counts(); authorizes != 5 || refunds != 5 {
				t.Fatalf("authorizes=%d refunds=%d, want 5/5", authorizes, refunds)
			}
		})
	}
}

func TestProviderCircuitFailoverSkipsOpenCandidatesAndFailsFastWhenAllOpen(t *testing.T) {
	enableProviderCircuitsForTest(t)
	const model = "circuit-pair/glm-5.3-flash"
	plane := newProviderCircuitControlPlane(t, model,
		providerCircuitTestCandidate{"circuit-alpha", "circuit-pair/glm-5.3-flash@circuit-alpha/prepaid"},
		providerCircuitTestCandidate{"circuit-beta", "circuit-pair/glm-5.3-flash@circuit-beta/prepaid"},
	)
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure("circuit-alpha", providerCircuitUpstreamStatus(503))
	const bearer = "circuit-pair-key" //nolint:gosec // deterministic public test fixture, not a credential

	// Alpha fails and beta serves; three failures open alpha for this tenant.
	for i := 1; i <= 3; i++ {
		response, body := serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("failover %d: status=%d body=%s, want 200", i, response.StatusCode, body)
		}
	}
	if alpha, beta := upstream.callsTo("circuit-alpha"), upstream.callsTo("circuit-beta"); alpha != 3 || beta != 3 {
		t.Fatalf("calls alpha=%d beta=%d, want 3/3", alpha, beta)
	}

	// Open alpha is skipped without a call, and the skip reaches settlement
	// analytics; beta still serves, so nothing fails fast.
	response, body := serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("skip: status=%d body=%s, want 200", response.StatusCode, body)
	}
	if alpha, beta := upstream.callsTo("circuit-alpha"), upstream.callsTo("circuit-beta"); alpha != 3 || beta != 4 {
		t.Fatalf("skip: calls alpha=%d beta=%d, want 3/4", alpha, beta)
	}
	plane.mu.Lock()
	lastSettle := plane.settled[len(plane.settled)-1]
	plane.mu.Unlock()
	failures, _ := lastSettle["route_failures"].([]any)
	if lastSettle["route_fallbacks"] != float64(1) || len(failures) != 1 || !strings.Contains(fmt.Sprint(failures[0]), "circuit-alpha|circuit-pair/glm-5.3-flash@circuit-alpha/prepaid|provider_circuit_open") {
		t.Fatalf("settlement route_failures = %v, want the skipped candidate", lastSettle["route_failures"])
	}

	// Beta goes down too. With alpha open, beta is the last candidate and is
	// tried with its retries; three failed requests open it.
	upstream.setFailure("circuit-beta", providerCircuitUpstreamStatus(503))
	for i := 1; i <= 3; i++ {
		response, body := serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
		if response.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("beta failure %d: status=%d body=%s, want relayed 503", i, response.StatusCode, body)
		}
		assertNotProviderCircuitRefusal(t, fmt.Sprintf("beta failure %d", i), response, body)
	}
	if alpha := upstream.callsTo("circuit-alpha"); alpha != 3 {
		t.Fatalf("open alpha was called: calls=%d, want 3", alpha)
	}
	authorizesBefore, refundsBefore, _ := plane.counts()

	// Both open: refused before authorize.
	response, body = serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	assertProviderCircuitRefusal(t, "all open", response, body, "60")
	if authorizes, refunds, _ := plane.counts(); authorizes != authorizesBefore || refunds != refundsBefore {
		t.Fatalf("all open reached the control plane: authorizes=%d->%d refunds=%d->%d", authorizesBefore, authorizes, refundsBefore, refunds)
	}
}

func TestProviderCircuitFailsFastOnMessages(t *testing.T) {
	enableProviderCircuitsForTest(t)
	const model = "circuit-messages/glm-5.3-flash"
	const provider = "circuit-messages"
	plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, "circuit-messages/glm-5.3-flash@circuit-messages/prepaid"})
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure(provider, providerCircuitUpstreamStatus(504))
	body := fmt.Sprintf(`{"model":%q,"max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`, model)
	for i := 1; i <= 3; i++ {
		response, responseBody := serveProviderCircuitRequest(t, plane, upstream, "circuit-messages-key", "/v1/messages", body)
		if response.StatusCode != http.StatusGatewayTimeout {
			t.Fatalf("failure %d: status=%d body=%s, want relayed 504", i, response.StatusCode, responseBody)
		}
	}
	response, responseBody := serveProviderCircuitRequest(t, plane, upstream, "circuit-messages-key", "/v1/messages", body)
	assertProviderCircuitRefusal(t, "messages fast fail", response, responseBody, "60")
	var envelope struct {
		Type  string `json:"type"`
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &envelope); err != nil || envelope.Type != "error" || envelope.Error.Type != "overloaded_error" {
		t.Fatalf("messages refusal is not Anthropic-shaped: %s", responseBody)
	}
	if authorizes, refunds, _ := plane.counts(); authorizes != 3 || refunds != 3 {
		t.Fatalf("messages fast fail reached the control plane: authorizes=%d refunds=%d, want 3/3", authorizes, refunds)
	}
}

// Authorize fits endpoints on ONE number, input + (max_tokens or 0)
// (quill-router candidates_fitting_context). The remembered set covers any
// request whose number is at least the remembered one, whatever the split, and
// never a request that needs less room.
func TestProviderCircuitDemandUsesTheControlPlaneContextFit(t *testing.T) {
	enableProviderCircuitsForTest(t)
	const model = "circuit-demand/glm-5.3-flash"
	const provider = "circuit-demand"
	plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, "circuit-demand/glm-5.3-flash@circuit-demand/prepaid"})
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure(provider, providerCircuitUpstreamStatus(502))
	body := func(maxTokens int, content string) string {
		return fmt.Sprintf(`{"model":%q,"max_tokens":%d,"messages":[{"role":"user","content":%q}]}`, model, maxTokens, content)
	}
	// Remembered: a short prompt with room for 1000 output tokens.
	for i := 0; i < 3; i++ {
		serveProviderCircuitRequest(t, plane, upstream, "circuit-demand-key", "/v1/chat/completions", body(1000, "hello"))
	}
	authorizesBefore, _, _ := plane.counts()
	// A long prompt with a small max_tokens needs MORE room in total: every
	// endpoint that fits it also fit the remembered request, so it is refused.
	response, responseBody := serveProviderCircuitRequest(t, plane, upstream, "circuit-demand-key", "/v1/chat/completions", body(100, strings.Repeat("long prompt ", 400)))
	assertProviderCircuitRefusal(t, "larger total demand", response, responseBody, "60")
	if authorizes, _, _ := plane.counts(); authorizes != authorizesBefore {
		t.Fatalf("larger total demand reached authorize: %d -> %d", authorizesBefore, authorizes)
	}
	// A request needing less room may fit an endpoint the remembered one was
	// filtered from, so it must reach authorize.
	serveProviderCircuitRequest(t, plane, upstream, "circuit-demand-key", "/v1/chat/completions", body(100, "hello"))
	if authorizes, _, _ := plane.counts(); authorizes != authorizesBefore+1 {
		t.Fatalf("a request needing less room was refused before authorize: %d -> %d", authorizesBefore, authorizes)
	}
}

// One model's outage must not refuse its siblings on the same provider, and a
// tenant's own BYOK account failing must not refuse anyone else's route.
func TestProviderCircuitKeepsSiblingModelsAndBYOKIsolated(t *testing.T) {
	enableProviderCircuitsForTest(t)
	down := providerCircuitUpstreamStatus(503)
	run := func(workspace string, options ...llm.InvokeOptions) (attempts int, err error) {
		calls := 0
		provider := streamingProviderFunc(func(_ context.Context, w io.Writer, option llm.InvokeOptions) error {
			calls++
			if strings.HasSuffix(option.EndpointID, "/down") {
				return down
			}
			_, writeErr := io.WriteString(w, providerStreamTestResponse)
			return writeErr
		})
		pr, pw := io.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			invokeProviderStream(context.Background(), provider, &types.OpenAIChatRequest{Model: options[0].Model},
				&types.AnthropicMessagesRequest{}, pw, options, true, &trustedrouter.Authorization{WorkspaceID: workspace},
				newSelectedRouteTracker(), "isolation-test", false, false)
		}()
		_, err = io.ReadAll(pr)
		<-done
		return calls, err
	}
	failing := llm.InvokeOptions{Provider: "circuit-sibling", Model: "circuit-sibling/glm-5.3-flash", EndpointID: "glm-5.3-flash/down", UsageType: "Credits"}
	sibling := llm.InvokeOptions{Provider: "circuit-sibling", Model: "circuit-sibling/glm-5.2", EndpointID: "glm-5.2/up", UsageType: "Credits"}
	for _, workspace := range []string{"ws-a", "ws-b", "ws-c"} {
		run(workspace, failing)
	}
	if calls, err := run("ws-d", failing); calls != 0 || err == nil {
		t.Fatalf("the failing model's shared circuit should be open: calls=%d err=%v", calls, err)
	}
	if calls, err := run("ws-d", sibling); calls != 1 || err != nil {
		t.Fatalf("a sibling model was refused: calls=%d err=%v", calls, err)
	}

	byok := llm.InvokeOptions{Provider: "circuit-byok", Model: "circuit-byok/model", EndpointID: "byok/down", UsageType: "BYOK"}
	platform := llm.InvokeOptions{Provider: "circuit-byok", Model: "circuit-byok/model", EndpointID: "prepaid/up", UsageType: "Credits"}
	for i := 0; i < 3; i++ {
		run("ws-byok-a", byok)
	}
	if calls, _ := run("ws-byok-a", byok); calls != 0 {
		t.Fatalf("a tenant's own failing BYOK route should be refused for that tenant: calls=%d", calls)
	}
	if calls, err := run("ws-byok-b", platform); calls != 1 || err != nil {
		t.Fatalf("one tenant's BYOK failures refused another tenant's platform route: calls=%d err=%v", calls, err)
	}
	if calls, err := run("ws-byok-a", platform); calls != 1 || err != nil {
		t.Fatalf("a tenant's BYOK failures refused its own platform route: calls=%d err=%v", calls, err)
	}
}

func TestProviderCircuitImagesRefusalCarriesRetryAfter(t *testing.T) {
	enableProviderCircuitsForTest(t)
	const model, provider = "google/gemini-3.1-flash-image", "google-ai-studio"
	var authorizes, refunds atomic.Int32
	gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		credential, _ := body["api_key_lookup_hash"].(string)
		response := `{"data":{"refunded":true}}`
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			authorizes.Add(1)
			encoded, _ := json.Marshal(map[string]any{"data": &trustedrouter.Authorization{
				AuthorizationID: "images-circuit", WorkspaceID: "ws_" + credential[:12], Model: model, Provider: provider,
				EndpointID: "served", UsageType: "Credits",
			}})
			response = string(encoded)
		case "/internal/gateway/refund":
			refunds.Add(1)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response)), Request: r}, nil
	})})
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure(provider, providerCircuitUpstreamStatus(503))
	body := fmt.Sprintf(`{"model":%q,"prompt":"cat"}`, model)
	for _, bearer := range []string{"images-a", "images-b", "images-c"} {
		var out bytes.Buffer
		serveImages(context.Background(), &out, upstream, []byte(body), gateway, bearer, nil, "", requestAttributionHeaders{}, "images-circuit")
	}
	before := upstream.total()
	var out bytes.Buffer
	serveImages(context.Background(), &out, upstream, []byte(body), gateway, "images-d", nil, "", requestAttributionHeaders{}, "images-circuit")
	response, responseBody := readRawHTTPResponse(t, out.Bytes())
	assertProviderCircuitRefusal(t, "images", response, responseBody, "60")
	if upstream.total() != before || authorizes.Load() != 4 || refunds.Load() != 4 {
		t.Fatalf("images refusal: upstream %d->%d authorizes=%d refunds=%d", before, upstream.total(), authorizes.Load(), refunds.Load())
	}
}

func TestProviderCircuitDecideRefusalCarriesRetryAfterWithoutASecondAttempt(t *testing.T) {
	enableProviderCircuitsForTest(t)
	down := fmt.Errorf("llm/upstream: http 503: unavailable")
	backend := &scriptedLLM{replies: make([]string, 8), errors: []error{down, down, down, down, down, down, down, down}}
	log := &controlPlaneLog{}
	controlPlane := fakeDecideControlPlane(t, log, "cerebras")
	gateway := trustedrouter.New(controlPlane.URL, "internal-token", controlPlane.Client())
	request := func() string {
		body := fmt.Sprintf(`{"model":%q,"state":%q,"questions":{"refund":{"type":"boolean","instructions":"Is a refund requested?"}}}`, decide.TrevModelID, privateState)
		var out bytes.Buffer
		serveDecide(context.Background(), &out, backend, []byte(body), gateway, true, "sk-tr-test-bearer", nil, "", requestAttributionHeaders{}, "log-circuit")
		return out.String()
	}
	request() // two refunded attempts
	request() // the third failure opens the tenant circuit; the next attempt is refused
	calls, authorizes, refunds := len(backend.requests), len(log.authorize), log.refund
	raw := request()
	response, body := readRawHTTPResponse(t, []byte(raw))
	assertProviderCircuitRefusal(t, "decide", response, body, "60")
	if len(backend.requests) != calls || len(log.authorize) != authorizes+1 || log.refund != refunds+1 {
		t.Fatalf("decide refusal: calls %d->%d authorizes %d->%d refunds %d->%d", calls, len(backend.requests), authorizes, len(log.authorize), refunds, log.refund)
	}
}

func TestProviderCircuitFusionRefusalCarriesRetryAfter(t *testing.T) {
	var out bytes.Buffer
	writeFusionError(context.Background(), &out, nil, fmt.Errorf("fusion panel: %w", &providerCircuitOpenError{retryAfter: 20 * time.Second}))
	response, body := readRawHTTPResponse(t, out.Bytes())
	assertProviderCircuitRefusal(t, "fusion", response, body, "20")
}

// runCircuitInvocation runs one invocation of options for workspace through
// invokeProviderStream with the given provider behaviour.
func runCircuitInvocation(ctx context.Context, workspace string, provider llm.Client, options ...llm.InvokeOptions) error {
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		invokeProviderStream(ctx, provider, &types.OpenAIChatRequest{Model: options[0].Model},
			&types.AnthropicMessagesRequest{}, pw, options, true, &trustedrouter.Authorization{WorkspaceID: workspace},
			newSelectedRouteTracker(), "circuit-invocation", false, false)
	}()
	_, err := io.ReadAll(pr)
	<-done
	return err
}

var circuitDown = streamingProviderFunc(func(context.Context, io.Writer, llm.InvokeOptions) error {
	return providerCircuitUpstreamStatus(503)
})

// A half-open probe that the provider accepted has proven the provider is
// back: it must free the route at acceptance, not after its whole stream.
func TestProviderCircuitAcceptedProbeFreesTheRouteWhileItStreams(t *testing.T) {
	clock := enableProviderCircuitsForTest(t)
	const model = "circuit-accept/glm-5.3-flash"
	const provider = "circuit-accept"
	plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, "circuit-accept/glm-5.3-flash@circuit-accept/prepaid"})
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure(provider, providerCircuitUpstreamStatus(503))
	openSharedCircuit(t, plane, upstream, model, "circuit-accept")
	clock.Advance(61 * time.Second)
	upstream.setFailure(provider, nil)

	entered, release := upstream.holdNextCall(true)
	defer release()
	probeDone := make(chan int, 1)
	go func() {
		raw := fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer circuit-accept-probe\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(chatBodyForCircuit(model, false)), chatBodyForCircuit(model, false))
		conn := newScriptedConn(raw, nil)
		serveOne(context.Background(), conn, auth.New(nil), upstream, nil, nil, plane.gateway, nil)
		response, err := http.ReadResponse(bufioReader(conn.writes.Bytes()), nil)
		if err != nil {
			probeDone <- 0
			return
		}
		probeDone <- response.StatusCode
	}()
	<-entered // the probe was accepted and its output is still flowing
	before := upstream.total()
	response, body := serveProviderCircuitRequest(t, plane, upstream, "circuit-accept-other", "/v1/chat/completions", chatBodyForCircuit(model, false))
	if response.StatusCode != http.StatusOK || upstream.total() != before+1 {
		t.Fatalf("another tenant was held off by an accepted probe: status=%d body=%s calls %d->%d", response.StatusCode, body, before, upstream.total())
	}
	release()
	if status := <-probeDone; status != http.StatusOK {
		t.Fatalf("probe status=%d, want 200", status)
	}
}

// A probe whose lease lapsed must not free the slot of the probe that
// replaced it.
func TestProviderCircuitLapsedProbeCannotReleaseItsSuccessor(t *testing.T) {
	clock := enableProviderCircuitsForTest(t)
	option := llm.InvokeOptions{Provider: "circuit-lease", Model: "circuit-lease/model", EndpointID: "lease", UsageType: "Credits"}
	const workspace = "ws-lease"
	tenant := providerCircuitTenant(&trustedrouter.Authorization{WorkspaceID: workspace})
	for i := 0; i < 3; i++ {
		_ = runCircuitInvocation(context.Background(), workspace, circuitDown, option)
	}
	clock.Advance(61 * time.Second)

	entered := make(chan struct{}, 2)
	hanging := streamingProviderFunc(func(ctx context.Context, _ io.Writer, _ llm.InvokeOptions) error {
		entered <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	start := func() (context.CancelFunc, chan struct{}) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = runCircuitInvocation(ctx, workspace, hanging, option)
		}()
		<-entered
		return cancel, done
	}
	cancelFirst, firstDone := start()
	clock.Advance(61 * time.Second) // the first probe's lease lapses
	cancelSecond, secondDone := start()
	defer func() { cancelSecond(); <-secondDone }()
	cancelFirst() // the old probe gives up while its successor is in flight
	<-firstDone
	if _, blocked := providerCircuits.Blocked(option, tenant); !blocked {
		t.Fatal("a lapsed probe freed its successor's slot: a second probe would be admitted")
	}
}

// Failure streaks age out: sporadic failures more than five open windows
// apart are noise, not an outage.
func TestProviderCircuitFailureStreaksAgeOut(t *testing.T) {
	clock := enableProviderCircuitsForTest(t)
	option := llm.InvokeOptions{Provider: "circuit-age", Model: "circuit-age/model", EndpointID: "age", UsageType: "Credits"}
	tenantOf := func(workspace string) string {
		return providerCircuitTenant(&trustedrouter.Authorization{WorkspaceID: workspace})
	}
	// Each check runs right after the third failure, while a circuit that
	// opened on it would still be open.
	spaced := func(gap time.Duration, workspaces ...string) {
		for i, workspace := range workspaces {
			if i > 0 {
				clock.Advance(gap)
			}
			_ = runCircuitInvocation(context.Background(), workspace, circuitDown, option)
		}
	}
	// One tenant, three failures six minutes apart: no open circuit.
	spaced(6*time.Minute, "ws-age-sporadic", "ws-age-sporadic", "ws-age-sporadic")
	if _, blocked := providerCircuits.Blocked(option, tenantOf("ws-age-sporadic")); blocked {
		t.Fatal("three failures six minutes apart opened the tenant circuit")
	}
	// Three tenants six minutes apart: no shared circuit.
	clock.Advance(6 * time.Minute)
	spaced(6*time.Minute, "ws-age-a", "ws-age-b", "ws-age-c")
	if _, blocked := providerCircuits.Blocked(option, tenantOf("ws-age-new")); blocked {
		t.Fatal("three tenants failing six minutes apart opened the shared circuit")
	}
	// The same failures two minutes apart are an outage.
	clock.Advance(6 * time.Minute)
	spaced(2*time.Minute, "ws-age-close", "ws-age-close", "ws-age-close")
	if _, blocked := providerCircuits.Blocked(option, tenantOf("ws-age-close")); !blocked {
		t.Fatal("three failures two minutes apart did not open the tenant circuit")
	}
	// An opened circuit left idle for more than five windows starts over: one
	// failure after that does not reopen it.
	clock.Advance(6 * time.Minute)
	_ = runCircuitInvocation(context.Background(), "ws-age-close", circuitDown, option)
	if _, blocked := providerCircuits.Blocked(option, tenantOf("ws-age-close")); blocked {
		t.Fatal("one failure after a long idle reopened an old circuit")
	}
}

type circuitCallerInputError struct{ err error }

func (e *circuitCallerInputError) Error() string              { return e.err.Error() }
func (e *circuitCallerInputError) Unwrap() error              { return e.err }
func (e *circuitCallerInputError) ClientInputMessage() string { return "invalid image input" }

// An image fetch that failed on our own control plane (a 5xx from
// fetch-image) is caller input, not the provider failing, even after the
// provider attempt's credential redaction rebuilt the error.
func TestProviderCircuitCountsNoCallerInputFailureAfterRedaction(t *testing.T) {
	_, redact := upstreamerror.WithCredentialRedaction(context.Background(), "provider-key")
	fetch := &circuitCallerInputError{err: fmt.Errorf("trustedrouter: /internal/gateway/fetch-image http 502: bad gateway")}
	if providerDownFailure(redact(fmt.Errorf("llm/openai: %w", fetch)), false) {
		t.Fatal("a redacted caller-input failure counted as the provider being down")
	}
}

// Fusion refused after panel members already settled must not tell the
// client a retry is free.
func TestProviderCircuitFusionRefusalAfterChargedPanelIsNotFreeToRetry(t *testing.T) {
	enableProviderCircuitsForTest(t)
	trGateway, recorder, closeGateway := newFusionGatewayRecorder(t)
	defer closeGateway()
	judge := llm.InvokeOptions{Provider: "test", Model: "circuit-judge/model", EndpointID: "circuit-judge/model@test/prepaid", UsageType: "Credits"}
	for i := 0; i < 3; i++ {
		_ = runCircuitInvocation(context.Background(), "ws_1", circuitDown, judge)
	}
	maxTokens := 512
	req := &types.OpenAIChatRequest{Model: trustedRouterLiberty40Model, MaxTokens: &maxTokens, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "Reply with a short local test answer."}}}
	config := fusionConfig{
		Enabled:             true,
		AnalysisModels:      []string{"circuit-panel-a/model", "circuit-panel-b/model"},
		SelectionStrategy:   "synthesize",
		MaxCompletionTokens: 512,
	}
	config.BuiltInPanelPrompt, config.BuiltInFinalPrompt = fusionBuiltInPrompts(false)
	var out bytes.Buffer
	serveFusionNonStreaming(context.Background(), &out, &fusionEchoLLM{}, req, config,
		[]string{"circuit-final/model"}, []string{judge.Model}, trGateway, nil, "local-liberty-key", req.Messages, "fusion-spent")
	response, body := readRawHTTPResponse(t, out.Bytes())
	recorder.mu.Lock()
	settled := len(recorder.settle)
	recorder.mu.Unlock()
	if settled == 0 {
		t.Fatalf("fixture: no panel member settled (status=%d body=%s)", response.StatusCode, body)
	}
	if response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Retry-After") == "" || response.Header.Get("X-Should-Retry") != "false" {
		t.Fatalf("status=%d headers=%v body=%s, want 503 with Retry-After and x-should-retry: false", response.StatusCode, response.Header, body)
	}
}

// circuitFailModelLLM answers 503 for one model (or for the calls fail
// selects) and delegates the rest.
type circuitFailModelLLM struct {
	inner llm.Client
	model string
	fail  func(*types.OpenAIChatRequest) bool
}

func (c circuitFailModelLLM) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	if req.Model == c.model || (c.fail != nil && c.fail(req)) {
		return providerCircuitUpstreamStatus(503)
	}
	return c.inner.InvokeStreaming(ctx, req, body, out, options...)
}

// assertChargedFailures runs an orchestration request four times while a
// later stage's model is down. Earlier stages settle every time, so every
// failure must say x-should-retry: false. With wantRefusal, the dead model's
// tenant circuit is open by the fourth request and the route must surface it
// as a 503 with Retry-After (still x-should-retry: false).
func assertChargedFailures(t *testing.T, wantRefusal bool, serve func() []byte) {
	t.Helper()
	for i := 1; i <= 4; i++ {
		response, body := readRawHTTPResponse(t, serve())
		if response.StatusCode < 500 || response.Header.Get("X-Should-Retry") != "false" {
			t.Fatalf("request %d after charged sub-calls: status=%d x-should-retry=%q body=%s", i, response.StatusCode, response.Header.Get("X-Should-Retry"), body)
		}
		if wantRefusal && i == 4 && (response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Retry-After") == "") {
			t.Fatalf("request 4: status=%d headers=%v body=%s, want the circuit refusal", response.StatusCode, response.Header, body)
		}
	}
}

func serveOrchestrationThroughServeOne(t *testing.T, trGateway *trustedrouter.Client, upstream llm.Client, requestBody string) []byte {
	t.Helper()
	raw := fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer bearer\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(requestBody), requestBody)
	conn := newScriptedConn(raw, nil)
	captureStderr(t, func() {
		serveOne(context.Background(), conn, auth.New(nil), upstream, nil, nil, trGateway, nil)
	})
	return append([]byte(nil), conn.writes.Bytes()...)
}

func TestProviderCircuitSelectorFailureAfterChargedPanelIsNotFreeToRetry(t *testing.T) {
	enableProviderCircuitsForTest(t)
	trGateway, _, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	upstream := circuitFailModelLLM{model: "model/selector", inner: &fusionEchoLLM{textByModel: map[string]string{"model/a": "first panel answer", "model/b": "best panel answer"}}}
	body := `{"model":"trustedrouter/selector","stream":false,"messages":[{"role":"user","content":"choose the best"}],"tools":[{"type":"trustedrouter:selector","parameters":{"analysis_models":["model/a","model/b"],"selector_models":["model/selector"],"max_completion_tokens":64}}],"max_tokens":64}`
	assertChargedFailures(t, true, func() []byte { return serveOrchestrationThroughServeOne(t, trGateway, upstream, body) })
}

func TestProviderCircuitMapReduceFailureAfterChargedStagesIsNotFreeToRetry(t *testing.T) {
	enableProviderCircuitsForTest(t)
	trGateway, _, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	upstream := circuitFailModelLLM{model: "model/reducer", inner: &fusionEchoLLM{
		textByModel:               map[string]string{"model/mapper": `{"parts":[{"title":"Alpha","prompt":"Part Alpha"},{"title":"Beta","prompt":"Part Beta"}]}`},
		textByLastMessageContains: map[string]string{"Part Alpha": "alpha result", "Part Beta": "beta result"},
	}}
	body := `{"model":"trustedrouter/mapreduce","stream":false,"messages":[{"role":"user","content":"solve a multi-part problem"}],"tools":[{"type":"trustedrouter:mapreduce","parameters":{"mapper_models":["model/mapper"],"parallel_models":["model/parallel"],"reducer_models":["model/reducer"],"max_parts":2,"max_completion_tokens":64}}],"max_tokens":64}`
	assertChargedFailures(t, true, func() []byte { return serveOrchestrationThroughServeOne(t, trGateway, upstream, body) })
}

func TestProviderCircuitAdvisorFailureAfterChargedWorkerIsNotFreeToRetry(t *testing.T) {
	enableProviderCircuitsForTest(t)
	trGateway, _, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	// The worker's first call (asking for advice) and the advisor settle; the
	// worker's follow-up and the advisor's fallback answer both fail.
	upstream := circuitFailModelLLM{inner: &advisorScriptedLLM{callAdviceFirst: true}, fail: func(req *types.OpenAIChatRequest) bool {
		switch req.Model {
		case "cerebras/gpt-oss-120b":
			return strings.Contains(lastChatMessageText(req.Messages), "advisor says") || strings.Contains(firstSystemMessageText(req.Messages), "advisor says")
		case "anthropic/claude-opus-4.8":
			return len(req.Messages) > 0 && strings.Contains(types.ContentText(req.Messages[0].Content), "worker model path failed")
		}
		return false
	}}
	config := testAdvisorConfig(t)
	assertChargedFailures(t, false, func() []byte {
		req := &types.OpenAIChatRequest{Model: trustedRouterSocrates10Model, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "review this risky migration"}}}
		var out bytes.Buffer
		captureStderr(t, func() {
			serveAdvisorNonStreaming(withRequestCharges(context.Background()), &out, upstream, req, config, trGateway, nil, "bearer", nil, "log_advisor_circuit")
		})
		return out.Bytes()
	})
}

func TestProviderCircuitSubagentFailureAfterChargedControllerIsNotFreeToRetry(t *testing.T) {
	enableProviderCircuitsForTest(t)
	trGateway, _, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	// The controller settles; its delegated worker is down, so the subagent
	// cannot complete.
	upstream := circuitFailModelLLM{model: "cerebras/gpt-oss-120b", inner: &subagentScriptedLLM{}}
	assertChargedFailures(t, false, func() []byte {
		req := &types.OpenAIChatRequest{
			Model:    "deepseek/deepseek-v4-flash",
			Messages: []types.OpenAIChatMessage{{Role: "user", Content: "Check deployment risk."}},
			Tools: []any{map[string]any{"type": openRouterSubagentTool, "parameters": map[string]any{
				"model": "cerebras/gpt-oss-120b", "instructions": "answer the delegated task tersely",
				"max_tool_calls": 2, "max_completion_tokens": 128,
			}}},
		}
		var out bytes.Buffer
		captureStderr(t, func() {
			if handled, err := maybeServeSubagent(context.Background(), &out, upstream, req, trGateway, nil, "bearer", nil, "log_subagent_circuit"); !handled || err != nil {
				t.Errorf("maybeServeSubagent handled=%t err=%v", handled, err)
			}
		})
		return out.Bytes()
	})
}

// A fusion whose panel members all settled but gave nothing usable, and one
// whose finals all refused after a billed panel and judge, both charged the
// request: neither may say a retry is free.
func TestProviderCircuitFusionAdapterFailuresAfterChargesAreNotFreeToRetry(t *testing.T) {
	enableProviderCircuitsForTest(t)
	trGateway, recorder, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	config := fusionConfig{Enabled: true, AnalysisModels: []string{"circuit-panel-a/model", "circuit-panel-b/model"}, SelectionStrategy: "synthesize", MaxCompletionTokens: 512}
	config.BuiltInPanelPrompt, config.BuiltInFinalPrompt = fusionBuiltInPrompts(false)
	maxTokens := 512
	for name, streamer := range map[string]*fusionEchoLLM{
		"empty panel answers": {textByModel: map[string]string{"circuit-panel-a/model": " ", "circuit-panel-b/model": " "}},
		"refusing finals":     {refusalModels: map[string]bool{"circuit-final/model": true}},
	} {
		t.Run(name, func(t *testing.T) {
			recorder.mu.Lock()
			settledBefore := len(recorder.settle)
			recorder.mu.Unlock()
			req := &types.OpenAIChatRequest{Model: trustedRouterLiberty40Model, MaxTokens: &maxTokens, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "Reply with a short local test answer."}}}
			cfg := config
			if name == "refusing finals" {
				cfg.SelectionStrategy = "synthesize_non_refusals"
			}
			var out bytes.Buffer
			captureStderr(t, func() {
				serveFusionNonStreaming(withRequestCharges(context.Background()), &out, streamer, req, cfg,
					[]string{"circuit-final/model"}, []string{"circuit-judge/model"}, trGateway, nil, "local-liberty-key", req.Messages, "fusion-charged")
			})
			response, body := readRawHTTPResponse(t, out.Bytes())
			recorder.mu.Lock()
			settled := len(recorder.settle) - settledBefore
			recorder.mu.Unlock()
			if settled == 0 {
				t.Fatalf("fixture: nothing settled (status=%d body=%s)", response.StatusCode, body)
			}
			if response.StatusCode == http.StatusOK || response.Header.Get("X-Should-Retry") != "false" {
				t.Fatalf("status=%d x-should-retry=%q body=%s, want a failure that says not to retry", response.StatusCode, response.Header.Get("X-Should-Retry"), body)
			}
		})
	}
}

// A provider that answers 2xx and then errors before any content has not
// shown it is up: the attempt is neither success nor failure. It must not
// wipe a streak of head-level failures or close a half-open circuit (it does
// free the probe slot at the head).
func TestProviderCircuitAcceptThenErrorIsNeitherSuccessNorFailure(t *testing.T) {
	clock := enableProviderCircuitsForTest(t)
	option := llm.InvokeOptions{Provider: "circuit-accept-error", Model: "circuit-accept-error/model", EndpointID: "accept-error", UsageType: "Credits"}
	const workspace = "ws-accept-error"
	tenant := providerCircuitTenant(&trustedrouter.Authorization{WorkspaceID: workspace})
	acceptThenError := streamingProviderFunc(func(_ context.Context, w io.Writer, _ llm.InvokeOptions) error {
		upstreamerror.Open(w)
		return &upstreamerror.Error{Status: 502, Body: `{"type":"error","error":{"message":"stream error"}}`}
	})
	_ = runCircuitInvocation(context.Background(), workspace, circuitDown, option)
	_ = runCircuitInvocation(context.Background(), workspace, circuitDown, option)
	_ = runCircuitInvocation(context.Background(), workspace, acceptThenError, option)
	_ = runCircuitInvocation(context.Background(), workspace, circuitDown, option)
	if _, blocked := providerCircuits.Blocked(option, tenant); !blocked {
		t.Fatal("an accepted-then-failed attempt wiped the streak of head-level failures")
	}
	clock.Advance(61 * time.Second)
	_ = runCircuitInvocation(context.Background(), workspace, acceptThenError, option)
	// The probe slot was freed at the head, and the circuit did not close: the
	// next failure reopens it at once.
	_ = runCircuitInvocation(context.Background(), workspace, circuitDown, option)
	if _, blocked := providerCircuits.Blocked(option, tenant); !blocked {
		t.Fatal("an accepted-then-failed probe closed the half-open circuit")
	}
}
