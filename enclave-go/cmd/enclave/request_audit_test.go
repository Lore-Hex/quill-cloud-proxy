package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/abuse"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/requesttiming"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestRequestEndLogsExplicitAbuseOutcomes(t *testing.T) {
	for _, outcome := range []string{abuse.OutcomeCachedReject, abuse.OutcomeRateLimited} {
		t.Run(outcome, func(t *testing.T) {
			var logLine bytes.Buffer
			writeRequestEndLog(
				&logLine, "rlog-test", "POST", "/v1/responses",
				http.StatusUnauthorized, 2, 2, time.Millisecond,
				requestAuditIdentity{}, outcome, requesttiming.FromContext(t.Context()).Snapshot(),
			)
			if !strings.Contains(logLine.String(), `outcome="`+outcome+`"`) {
				t.Fatalf("missing outcome %q: %s", outcome, logLine.String())
			}
		})
	}
}

func TestRequestContractRejectionLogIsMetadataOnlyAndBounded(t *testing.T) {
	var logLine bytes.Buffer
	parameter := strings.Repeat("future_option", 30)
	writeRequestContractRejection(
		&logLine,
		"rlog-contract",
		"/v1/chat/completions",
		http.StatusBadRequest,
		parameter,
	)
	logged := logLine.String()
	for _, want := range []string{
		`enclave.request_contract_rejected`,
		`request_log_id="rlog-contract"`,
		`route="/v1/chat/completions"`,
		`status=400`,
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("contract log missing %q: %s", want, logged)
		}
	}
	if strings.Contains(logged, parameter) || len(logged) > 320 {
		t.Fatalf("contract log was not bounded: %s", logged)
	}
}

func TestRequestContractRejectionLogUsesPublicCategoriesOnly(t *testing.T) {
	for _, tc := range []struct{ parameter, category string }{
		{"store", "store"},
		{"store=true", "store"},
		{"tools.private-customer-value", "tools"},
		{"input[123].private-customer-value", "input"},
		{"private-customer-value", "other"},
		{"sk-tr-v1-private-credential", "other"},
		{"alice@example.com", "other"},
	} {
		t.Run(tc.parameter, func(t *testing.T) {
			var logLine bytes.Buffer
			writeRequestContractRejection(&logLine, "rlog-contract", "/v1/responses", 501, tc.parameter)
			logged := logLine.String()
			if !strings.Contains(logged, `parameter="`+tc.category+`"`) {
				t.Fatalf("missing safe category %q: %s", tc.category, logged)
			}
			for _, secret := range []string{"private-customer-value", "sk-tr-v1-", "alice@", "=true"} {
				if strings.Contains(logged, secret) {
					t.Fatalf("private parameter data reached log: %s", logged)
				}
			}
		})
	}
}

func TestRequestAuditResolvesWorkspaceForPreAuthorizationError(t *testing.T) {
	const bearer = "synthetic-private-bearer-material"
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read validation body: %v", err)
		}
		if bytes.Contains(body, []byte(bearer)) {
			t.Fatalf("raw bearer reached control plane: %s", body)
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode validation body: %v", err)
		}
		_, _ = io.WriteString(w, `{"data":{"workspace_id":"ws-customer","api_key_hash":"stored-key-digest"}}`)
	}))
	defer server.Close()

	identity := requestAuditIdentity{}
	identity.bindBearer(bearer)
	identity.resolveFailure(
		t.Context(),
		trustedrouter.New(server.URL, "internal", server.Client()),
		bearer,
		"/v1/responses",
		http.StatusNotImplemented,
	)

	if identity.workspaceID != "ws-customer" || identity.credentialID != "stored-key-digest" {
		t.Fatalf("identity = %#v", identity)
	}
	if identity.attribution != "validation" {
		t.Fatalf("attribution = %q", identity.attribution)
	}
	if got := payload["api_key_lookup_hash"]; got != trustedrouter.LookupHash(bearer) {
		t.Fatalf("lookup hash = %#v", got)
	}
	if got := payload["route_type"]; got != "/v1/responses" {
		t.Fatalf("route type = %#v", got)
	}

	var logLine bytes.Buffer
	writeRequestEndLog(
		&logLine,
		"req-log-1",
		"POST",
		"/v1/responses",
		http.StatusNotImplemented,
		100,
		80,
		12*time.Millisecond,
		identity,
		"",
		requesttiming.FromContext(t.Context()).Snapshot(),
	)
	logged := logLine.String()
	for _, want := range []string{
		`workspace_id="ws-customer"`,
		`credential_id="stored-key-digest"`,
		`credential_fingerprint="` + trustedrouter.LookupHash(bearer) + `"`,
		`attribution="validation"`,
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("request end log missing %q: %s", want, logged)
		}
	}
	if strings.Contains(logged, bearer) {
		t.Fatalf("request end log leaked bearer: %s", logged)
	}
}

func TestRequestAuditDoesNotValidateSuccessfulRequest(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = io.WriteString(w, `{"data":{"workspace_id":"unexpected","api_key_hash":"unexpected"}}`)
	}))
	defer server.Close()

	identity := requestAuditIdentity{}
	identity.bindBearer("sk-tr-v1-success")
	identity.resolveFailure(
		t.Context(),
		trustedrouter.New(server.URL, "internal", server.Client()),
		"sk-tr-v1-success",
		"/v1/chat/completions",
		http.StatusOK,
	)
	if calls != 0 {
		t.Fatalf("successful request triggered %d identity lookups", calls)
	}
	if identity.workspaceID != "" || identity.attribution != "fingerprint_only" {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestRequestAuditAuthorizationAvoidsFailureLookup(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	identity := requestAuditIdentity{}
	identity.bindBearer("sk-tr-v1-authorized")
	identity.bindAuthorization(&trustedrouter.Authorization{
		WorkspaceID: "ws-authorized",
		APIKeyHash:  "stored-key-authorized",
	})
	identity.resolveFailure(
		t.Context(),
		trustedrouter.New(server.URL, "internal", server.Client()),
		"sk-tr-v1-authorized",
		"/v1/chat/completions",
		http.StatusBadGateway,
	)
	if calls != 0 {
		t.Fatalf("authorized failure triggered %d redundant identity lookups", calls)
	}
	if identity.workspaceID != "ws-authorized" || identity.attribution != "authorization" {
		t.Fatalf("identity = %#v", identity)
	}
}

// The shared clock advances only at explicit phase boundaries, even when the
// provider and handler run on different goroutines.
type phaseAuditClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *phaseAuditClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *phaseAuditClock) advance(ms int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(time.Duration(ms) * time.Millisecond)
}

type phaseAuditConn struct {
	*scriptedConn
	clock  *phaseAuditClock
	phases *requesttiming.Timer
}

func (c *phaseAuditConn) Read(p []byte) (int, error) {
	c.clock.advance(8)
	return c.scriptedConn.Read(p)
}
func (c *phaseAuditConn) Write(p []byte) (int, error) {
	// Streaming headers/chunks may be written during provider work. Advance
	// response time only after provider completion in this partition test.
	if c.phases.Snapshot().UpstreamMS != 0 {
		c.clock.advance(8)
	}
	return c.scriptedConn.Write(p)
}

type phaseAuditLLM struct {
	fakeEmbeddingLLM
	clock *phaseAuditClock
}

func (p *phaseAuditLLM) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	p.clock.advance(12)
	var bodyBytes bytes.Buffer
	if err := p.fakeStreamingLLM.InvokeStreaming(ctx, req, body, &bodyBytes, options...); err != nil {
		return err
	}
	// EOF terminates this fixture so completion precedes settlement. Separate
	// tests exercise message_stop and disconnect before provider completion.
	stream := strings.Replace(bodyBytes.String(), "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", "", 1)
	_, err := io.WriteString(out, stream)
	return err
}
func (p *phaseAuditLLM) InvokeEmbedding(ctx context.Context, req *types.EmbeddingRequest, options ...llm.InvokeOptions) (*types.EmbeddingResponse, error) {
	p.clock.advance(12)
	return p.fakeEmbeddingLLM.InvokeEmbedding(ctx, req, options...)
}

var auditFieldPattern = regexp.MustCompile(`([a-z_]+)=("(?:[^"\\]|\\.)*"|[^ ]+)`)

func parseAuditEvent(t *testing.T, logs, event string) map[string]string {
	t.Helper()
	for _, line := range strings.Split(logs, "\n") {
		if !strings.HasPrefix(line, event+" ") {
			continue
		}
		// No general request_end cap exists in the log writers/collectors. Keep
		// this ordinary synthetic line comfortably under 2 KiB (Scanner is 64 KiB).
		if event == "enclave.request_end" && len(line) >= 2048 {
			t.Fatalf("oversized request_end: %d bytes", len(line))
		}
		fields := map[string]string{}
		for _, match := range auditFieldPattern.FindAllStringSubmatch(line, -1) {
			value := match[2]
			if strings.HasPrefix(value, `"`) {
				var err error
				value, err = strconv.Unquote(value)
				if err != nil {
					t.Fatal(err)
				}
			}
			fields[match[1]] = value
		}
		return fields
	}
	t.Fatalf("missing %s in %s", event, logs)
	return nil
}

func TestRequestEndPhaseTimings(t *testing.T) {
	for _, tc := range []struct {
		name, route, body, settle string
		retry, noGateway          bool
	}{
		{name: "chat", route: "chat/completions", body: replayTestRequestBody, settle: "ok"},
		{name: "chat_stream", route: "chat/completions", body: strings.Replace(replayTestRequestBody, `"stream":false`, `"stream":true`, 1), settle: "ok"},
		{name: "responses", route: "responses", body: `{"model":"openai/gpt-4o-mini","input":"private-input"}`, settle: "ok"},
		{name: "responses_stream", route: "responses", body: `{"model":"openai/gpt-4o-mini","input":"private-input","stream":true}`, settle: "ok"},
		{name: "embeddings", route: "embeddings", body: `{"model":"openai/gpt-4o-mini","input":"private-input"}`, settle: "ok"},
		{name: "authorize_retry", route: "chat/completions", body: replayTestRequestBody, settle: "ok", retry: true},
		{name: "settle_failed", route: "chat/completions", body: replayTestRequestBody, settle: "failed"},
		{name: "settle_deferred", route: "chat/completions", body: replayTestRequestBody, settle: "deferred"},
		{name: "settle_skipped", route: "chat/completions", body: replayTestRequestBody, settle: "skipped", noGateway: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &phaseAuditClock{now: time.Unix(1000, 0)}
			phases := requesttiming.New(clock.Now(), clock.Now)
			ctx := requesttiming.WithTimer(context.Background(), phases)
			router := newReplayRouterDouble()
			router.firstAttempt503 = tc.retry
			gateway := trustedrouter.New("https://trustedrouter.com", "private-internal-key", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/internal/gateway/authorize" || r.URL.Path == "/internal/gateway/settle" {
					clock.advance(10)
				}
				if r.URL.Path == "/internal/gateway/settle" {
					switch tc.settle {
					case "failed":
						return replayHTTPResponse(r, 400, `{"error":{"message":"synthetic failure"}}`), nil
					case "deferred":
						return replayHTTPResponse(r, 200, `{"data":{"disposition":"intent_durable"}}`), nil
					}
				}
				return router.roundTrip(r)
			})})
			if tc.noGateway {
				gateway = nil
			}
			raw := fmt.Sprintf("POST /v1/%s HTTP/1.1\r\nAuthorization: Bearer private-bearer\r\nIdempotency-Key: phase-test\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", tc.route, len(tc.body), tc.body)
			conn := &phaseAuditConn{newScriptedConn(raw, nil), clock, phases}
			logs := captureProviderStreamStderr(t, func() *providerInvocation {
				serveOne(ctx, conn, registryForBearer("private-bearer"), &phaseAuditLLM{clock: clock}, nil, nil, gateway, nil)
				return nil // successful provider EOF follows invoke_complete
			})
			end := parseAuditEvent(t, logs, "enclave.request_end")
			nums := map[string]int64{}
			for _, key := range []string{"idle_wait_ms", "request_ms", "accept_to_start_ms", "authorize_ms", "authorize_attempts", "route_ms", "upstream_ms", "upstream_partial", "ttfb_ms", "retry_wait_ms", "settle_ms", "receipt_ms", "elapsed_ms"} {
				value, exists := end[key]
				if !exists {
					t.Fatalf("missing %s: %v", key, end)
				}
				n, err := strconv.ParseInt(value, 10, 64)
				if err != nil || n < 0 {
					t.Fatalf("invalid %s=%q", key, value)
				}
				nums[key] = n
			}
			for _, key := range []string{"settle_outcome", "cp_endpoint"} {
				if _, ok := end[key]; !ok {
					t.Fatalf("missing %s", key)
				}
			}
			if nums["accept_to_start_ms"] != 8 || nums["upstream_ms"] != 12 || nums["upstream_partial"] != 0 || nums["receipt_ms"] < 8 {
				t.Fatalf("phase assignment missing: %v", end)
			}
			if end["settle_outcome"] != tc.settle {
				t.Fatalf("settle_outcome=%q want %q", end["settle_outcome"], tc.settle)
			}
			if tc.noGateway {
				if nums["authorize_ms"] != 0 || nums["authorize_attempts"] != 0 || nums["settle_ms"] != 0 || end["cp_endpoint"] != "" {
					t.Fatalf("unexpected control plane phase: %v", end)
				}
			} else {
				attempts := int64(1)
				if tc.retry {
					attempts = 2
				}
				if nums["authorize_ms"] != 10*attempts || nums["authorize_attempts"] != attempts || nums["settle_ms"] != 10 || end["cp_endpoint"] != "trustedrouter.com" {
					t.Fatalf("control plane phase missing: %v", end)
				}
			}
			wantTTFB := int64(12)
			if tc.route == "embeddings" {
				wantTTFB = 0
			}
			if nums["ttfb_ms"] != wantTTFB {
				t.Fatalf("ttfb=%d want %d", nums["ttfb_ms"], wantTTFB)
			}
			sum := nums["accept_to_start_ms"] + nums["authorize_ms"] + nums["route_ms"] + nums["upstream_ms"] + nums["retry_wait_ms"] + nums["settle_ms"] + nums["receipt_ms"]
			if sum != nums["request_ms"] || nums["idle_wait_ms"] != 0 || nums["request_ms"] != nums["elapsed_ms"] {
				t.Fatalf("phase sum=%d request=%d: %v", sum, nums["request_ms"], end)
			}
			for _, secret := range []string{"private-bearer", "private-internal-key", "private-input", "Hello world"} {
				if strings.Contains(logs, secret) {
					t.Fatalf("secret in audit log: %s", secret)
				}
			}
			response, _ := readRawHTTPResponse(t, conn.writes.Bytes())
			wantStatus := 200
			if tc.settle == "failed" {
				wantStatus = 502
			}
			if response.StatusCode != wantStatus {
				t.Fatalf("response=%d want %d", response.StatusCode, wantStatus)
			}
		})
	}
}

func TestRequestEndPhaseTimingsRejectedBeforeInvoke(t *testing.T) {
	conn := newScriptedConn("POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{", nil)
	logs := captureProviderStreamStderr(t, func() *providerInvocation {
		serveOne(context.Background(), conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, nil, nil)
		return nil
	})
	end := parseAuditEvent(t, logs, "enclave.request_end")
	for _, key := range []string{"authorize_ms", "authorize_attempts", "route_ms", "upstream_ms", "ttfb_ms", "retry_wait_ms", "settle_ms", "receipt_ms"} {
		if end[key] != "0" {
			t.Fatalf("missing phase %s=%q", key, end[key])
		}
	}
	if end["settle_outcome"] != "skipped" || end["cp_endpoint"] != "" {
		t.Fatalf("missing phases: %v", end)
	}
}

// Hold the provider past handler return without adding any production join.
type phaseHeldLLM struct {
	fakeStreamingLLM
	clock      *phaseAuditClock
	release    <-chan struct{}
	disconnect bool
}

func (p *phaseHeldLLM) InvokeStreaming(ctx context.Context, req *types.OpenAIChatRequest, body *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	p.clock.advance(12)
	var stream bytes.Buffer
	_ = p.fakeStreamingLLM.InvokeStreaming(ctx, req, body, &stream, options...)
	data := stream.String()
	if p.disconnect {
		// Send a nonterminal chunk and wait for the test's client write failure.
		data = strings.Split(data, "event: message_delta")[0]
	}
	_, err := io.WriteString(out, data)
	<-p.release
	return err
}

type phaseDisconnectWriter struct {
	bytes.Buffer
	clock                 *phaseAuditClock
	disconnect, delivered bool
}

func (w *phaseDisconnectWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("Hello")) && !w.delivered {
		w.delivered = true
		w.clock.advance(5)
		if w.disconnect {
			return 0, io.ErrClosedPipe
		}
	}
	return w.Buffer.Write(p)
}

func TestStreamingPhaseEndBeforeProviderComplete(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		name := "message_stop"
		if disconnect {
			name = "client_disconnect"
		}
		t.Run(name, func(t *testing.T) {
			clock := &phaseAuditClock{now: time.Unix(1000, 0)}
			phases := requesttiming.New(clock.Now(), clock.Now)
			phases.Start()
			ctx := requesttiming.WithTimer(t.Context(), phases)
			req := &types.OpenAIChatRequest{Model: "test-model", Stream: true}
			release := make(chan struct{})
			backend := &phaseHeldLLM{clock: clock, release: release, disconnect: disconnect}
			out := &phaseDisconnectWriter{clock: clock, disconnect: disconnect}
			var before requesttiming.Fields
			logs := captureProviderStreamStderr(t, func() *providerInvocation {
				invocation := startProviderInvocation(ctx, backend, req, &types.AnthropicMessagesRequest{}, nil, false, nil, "phase-held")
				// Cleanup releases the provider even if a regression makes an assertion fail.
				defer close(release)
				ctx = withProviderInvocation(ctx, invocation)
				serveStreaming(ctx, out, backend, req, &types.AnthropicMessagesRequest{}, nil, nil, nil, nil, time.Now(), nil, "chat.completions", "phase-held", req.Model)
				elapsed := phases.End()
				before = phases.Snapshot()
				writeRequestEndLog(&out.Buffer, "phase-held", "POST", "/v1/chat/completions", 200, 0, 0, elapsed, requestAuditIdentity{}, "", before)
				if !out.delivered || before.UpstreamMS != 17 || before.TTFBMS != 12 || before.UpstreamPartial != 1 || elapsed != 17*time.Millisecond {
					t.Errorf("unfinished stream: delivered=%v elapsed=%v phases=%+v", out.delivered, elapsed, before)
				}
				clock.advance(100)
				return invocation // capture helper joins only after End has frozen the fields
			})
			if after := phases.Snapshot(); after != before {
				t.Fatalf("late completion changed fields: %+v -> %+v", before, after)
			}
			if !strings.Contains(logs, "enclave.invoke_complete") {
				t.Fatal("provider did not finish")
			}
			if !strings.Contains(out.String(), "upstream_partial=1") {
				t.Fatal("partial marker missing from request_end")
			}
		})
	}
}
