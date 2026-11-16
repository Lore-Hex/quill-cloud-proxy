package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

// TestMain isolates the process-wide provider circuit registry. Package tests
// share one process, so provider failures that one test scripts would open
// circuits for the next. Tests that exercise the breaker enable it with
// enableProviderCircuitsForTest and their own provider names.
func TestMain(m *testing.M) {
	providerCircuits.mu.Lock()
	providerCircuits.enabled = false
	providerCircuits.mu.Unlock()
	os.Exit(m.Run())
}

type providerCircuitTestClock struct{ nanos atomic.Int64 }

func newProviderCircuitTestClock() *providerCircuitTestClock {
	clock := &providerCircuitTestClock{}
	clock.nanos.Store(time.Date(2026, 11, 16, 18, 45, 0, 0, time.UTC).UnixNano())
	return clock
}

func (c *providerCircuitTestClock) Now() time.Time          { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *providerCircuitTestClock) Advance(d time.Duration) { c.nanos.Add(int64(d)) }

// enableProviderCircuitsForTest turns on the production defaults (threshold 3,
// 60 s open window) against a controllable clock, and makes same-provider
// retry backoff instant.
func enableProviderCircuitsForTest(t *testing.T) *providerCircuitTestClock {
	t.Helper()
	t.Setenv("QUILL_KEEPALIVE", "off")
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	clock := newProviderCircuitTestClock()
	registry := providerCircuits
	registry.mu.Lock()
	registry.enabled = true
	registry.threshold = 3
	registry.openFor = time.Minute
	registry.now = clock.Now
	registry.states = map[string]providerCircuitState{}
	registry.mu.Unlock()
	oldSleep := sleepBeforeTransientRetry
	sleepBeforeTransientRetry = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	t.Cleanup(func() {
		sleepBeforeTransientRetry = oldSleep
		registry.mu.Lock()
		registry.enabled = false
		registry.now = time.Now
		registry.states = map[string]providerCircuitState{}
		registry.mu.Unlock()
	})
	return clock
}

type providerCircuitTestCandidate struct {
	provider string
	endpoint string
}

// providerCircuitControlPlane is a fake control plane that counts the billing
// calls the breaker exists to avoid.
type providerCircuitControlPlane struct {
	server     *httptest.Server
	gateway    *trustedrouter.Client
	authorizes atomic.Int32
	refunds    atomic.Int32
	settles    atomic.Int32
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
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			n := plane.authorizes.Add(1)
			encoded, _ := json.Marshal(map[string]any{"data": map[string]any{
				"authorization_id": fmt.Sprintf("auth_circuit_%d", n),
				"workspace_id":     "ws_circuit", "api_key_hash": "key_circuit",
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

// providerCircuitTestUpstream fails per provider as scripted and records every
// upstream call it receives.
type providerCircuitTestUpstream struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]error
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
	u.mu.Unlock()
	if err != nil {
		return err
	}
	_, err = io.WriteString(out, providerStreamTestResponse)
	return err
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

func TestProviderCircuitOpensAndFailsFastBeforeAuthorize(t *testing.T) {
	clock := enableProviderCircuitsForTest(t)
	const model = "circuit-solo/glm-5.3-flash"
	const provider = "circuit-solo"
	plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, "circuit-solo/glm-5.3-flash@circuit-solo/prepaid"})
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure(provider, providerCircuitUpstreamStatus(502))
	const bearer = "circuit-solo-key"

	// Three failed requests (each tries the provider three times before
	// giving up) open the circuit. Each one is authorized and refunded.
	for i := 1; i <= 3; i++ {
		response, body := serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
		if response.StatusCode != http.StatusBadGateway {
			t.Fatalf("failure %d: status=%d body=%s, want relayed 502", i, response.StatusCode, body)
		}
		assertNotProviderCircuitRefusal(t, fmt.Sprintf("failure %d", i), response, body)
	}
	if authorizes, refunds, _ := plane.counts(); authorizes != 3 || refunds != 3 {
		t.Fatalf("after opening: authorizes=%d refunds=%d, want 3/3", authorizes, refunds)
	}
	if got := upstream.total(); got != 9 {
		t.Fatalf("upstream calls=%d, want 9", got)
	}

	// The fourth request is refused before authorize: no hold, no refund, no
	// upstream call, and the client is told when to come back.
	response, body := serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	assertProviderCircuitRefusal(t, "fast fail", response, body, "60")
	if authorizes, refunds, _ := plane.counts(); authorizes != 3 || refunds != 3 {
		t.Fatalf("fast fail reached the control plane: authorizes=%d refunds=%d, want 3/3", authorizes, refunds)
	}
	if got := upstream.total(); got != 9 {
		t.Fatalf("fast fail called the provider: upstream calls=%d, want 9", got)
	}

	// The 30 s route memory has expired 45 s later, so this request is
	// authorized; its only candidate is still open, so it is refused without a
	// provider call and refunded. Retry-After counts down with the window.
	clock.Advance(45 * time.Second)
	response, body = serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	assertProviderCircuitRefusal(t, "after route memory expiry", response, body, "15")
	if authorizes, refunds, _ := plane.counts(); authorizes != 4 || refunds != 4 {
		t.Fatalf("after route memory expiry: authorizes=%d refunds=%d, want 4/4", authorizes, refunds)
	}
	if got := upstream.total(); got != 9 {
		t.Fatalf("open circuit was called: upstream calls=%d, want 9", got)
	}
	// That authorize refreshed the memory, so the next one fails fast again.
	response, body = serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	assertProviderCircuitRefusal(t, "refreshed fast fail", response, body, "15")
	if authorizes, _, _ := plane.counts(); authorizes != 4 {
		t.Fatalf("refreshed fast fail authorized: authorizes=%d, want 4", authorizes)
	}

	// After the open window one probe goes through, succeeds and closes it.
	clock.Advance(16 * time.Second)
	upstream.setFailure(provider, nil)
	response, body = serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("probe: status=%d body=%s, want 200", response.StatusCode, body)
	}
	if got := upstream.total(); got != 10 {
		t.Fatalf("probe upstream calls=%d, want 10", got)
	}
	response, body = serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("after close: status=%d body=%s, want 200", response.StatusCode, body)
	}
	if authorizes, refunds, settles := plane.counts(); authorizes != 6 || refunds != 4 || settles != 2 {
		t.Fatalf("after close: authorizes=%d refunds=%d settles=%d, want 6/4/2", authorizes, refunds, settles)
	}
}

func TestProviderCircuitNewCredentialIsRefusedWithoutProviderCall(t *testing.T) {
	enableProviderCircuitsForTest(t)
	const model = "circuit-fresh/glm-5.3-flash"
	const provider = "circuit-fresh"
	plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, "circuit-fresh/glm-5.3-flash@circuit-fresh/prepaid"})
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure(provider, providerCircuitUpstreamStatus(503))
	for i := 0; i < 3; i++ {
		serveProviderCircuitRequest(t, plane, upstream, "circuit-fresh-first-key", "/v1/chat/completions", chatBodyForCircuit(model, true))
	}
	before := upstream.total()

	// A credential with no remembered route is authorized (the gateway cannot
	// know its candidates yet), but the open circuit is not called and the
	// streaming client still gets the 503 with Retry-After before any head.
	response, body := serveProviderCircuitRequest(t, plane, upstream, "circuit-fresh-second-key", "/v1/chat/completions", chatBodyForCircuit(model, true))
	assertProviderCircuitRefusal(t, "new credential", response, body, "60")
	if authorizes, refunds, _ := plane.counts(); authorizes != 4 || refunds != 4 {
		t.Fatalf("new credential: authorizes=%d refunds=%d, want 4/4", authorizes, refunds)
	}
	if got := upstream.total(); got != before {
		t.Fatalf("new credential called the open circuit: upstream calls=%d, want %d", got, before)
	}
	// Its next request is refused before authorize.
	response, body = serveProviderCircuitRequest(t, plane, upstream, "circuit-fresh-second-key", "/v1/chat/completions", chatBodyForCircuit(model, true))
	assertProviderCircuitRefusal(t, "new credential repeat", response, body, "60")
	if authorizes, refunds, _ := plane.counts(); authorizes != 4 || refunds != 4 {
		t.Fatalf("new credential repeat: authorizes=%d refunds=%d, want 4/4", authorizes, refunds)
	}
}

func TestProviderCircuitFailedProbeReopensAfterOneCall(t *testing.T) {
	clock := enableProviderCircuitsForTest(t)
	const model = "circuit-probe/glm-5.3-flash"
	const provider = "circuit-probe"
	plane := newProviderCircuitControlPlane(t, model, providerCircuitTestCandidate{provider, "circuit-probe/glm-5.3-flash@circuit-probe/prepaid"})
	upstream := &providerCircuitTestUpstream{}
	upstream.setFailure(provider, providerCircuitUpstreamStatus(502))
	const bearer = "circuit-probe-key"
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
	const bearer = "circuit-pair-key"

	// Alpha fails and beta serves; three failures open alpha.
	for i := 1; i <= 3; i++ {
		response, body := serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("failover %d: status=%d body=%s, want 200", i, response.StatusCode, body)
		}
	}
	if alpha, beta := upstream.callsTo("circuit-alpha"), upstream.callsTo("circuit-beta"); alpha != 3 || beta != 3 {
		t.Fatalf("calls alpha=%d beta=%d, want 3/3", alpha, beta)
	}

	// Open alpha is skipped without a call; beta still serves, so nothing
	// fails fast.
	response, body := serveProviderCircuitRequest(t, plane, upstream, bearer, "/v1/chat/completions", chatBodyForCircuit(model, false))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("skip: status=%d body=%s, want 200", response.StatusCode, body)
	}
	if alpha, beta := upstream.callsTo("circuit-alpha"), upstream.callsTo("circuit-beta"); alpha != 3 || beta != 4 {
		t.Fatalf("skip: calls alpha=%d beta=%d, want 3/4", alpha, beta)
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
