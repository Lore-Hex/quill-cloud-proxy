package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// An authorize holds the caller's credit until a settle or a refund closes it.
// These tests drive the exits that left a hold open, and the ones that must
// never place one, against a control plane that records every billing call.

// holdLedger is a control plane that authorizes everything and records what it
// was sent. settleStatus and refundStatus fail every such call with that
// status; zero succeeds.
type holdLedger struct {
	mu                         sync.Mutex
	authorizes                 int
	settles                    int
	validations                int
	refunds                    []map[string]any
	settleStatus, refundStatus int
}

func (l *holdLedger) gateway(t *testing.T) *trustedrouter.Client {
	t.Helper()
	return trustedrouter.New("https://trustedrouter.com", "internal-token", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			respond := func(status int, payload string) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
			}
			failure := func(status int) (*http.Response, error) {
				return respond(status, fmt.Sprintf(`{"error":{"message":"control plane says %d","type":"test"}}`, status))
			}
			l.mu.Lock()
			defer l.mu.Unlock()
			switch r.URL.Path {
			case "/internal/gateway/authorize":
				l.authorizes++
				model, _ := body["model"].(string)
				return respond(200, fmt.Sprintf(
					`{"data":{"authorization_id":"auth_%d","workspace_id":"ws_1","api_key_hash":"key_1","model":%q,"endpoint_id":"e@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`,
					l.authorizes, model,
				))
			case "/internal/gateway/settle":
				l.settles++
				if l.settleStatus != 0 {
					return failure(l.settleStatus)
				}
				return respond(200, `{"data":{"settled":true,"generation_id":"gen_1","cost_microdollars":12,"model":"m","provider":"openai","region":"us-central1"}}`)
			case "/internal/gateway/refund":
				l.refunds = append(l.refunds, body)
				if l.refundStatus != 0 {
					return failure(l.refundStatus)
				}
				return respond(200, `{"data":{"refunded":true}}`)
			case "/internal/gateway/validate":
				l.validations++
				return respond(200, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1"}}`)
			}
			t.Errorf("unexpected control-plane path %s", r.URL.Path)
			return failure(500)
		}),
	})
}

// calls returns the authorize, settle and refund counts.
func (l *holdLedger) calls() (authorizes, settles, refunds int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authorizes, l.settles, len(l.refunds)
}

// refundTypes returns the error_type of each refund, in order.
func (l *holdLedger) refundTypes() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.refunds))
	for _, refund := range l.refunds {
		errorType, _ := refund["error_type"].(string)
		out = append(out, errorType)
	}
	return out
}

func (l *holdLedger) validated() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.validations
}

// wantCalls fails unless the control plane saw exactly these counts.
func (l *holdLedger) wantCalls(t *testing.T, authorizes, settles, refunds int) {
	t.Helper()
	gotAuthorizes, gotSettles, gotRefunds := l.calls()
	if gotAuthorizes != authorizes || gotSettles != settles || gotRefunds != refunds {
		t.Fatalf("control plane saw authorize=%d settle=%d refund=%d (%v), want authorize=%d settle=%d refund=%d",
			gotAuthorizes, gotSettles, gotRefunds, l.refundTypes(), authorizes, settles, refunds)
	}
}

// isolateSettlementRetries gives the test its own retry queue, which nothing
// drains, and returns it.
func isolateSettlementRetries(t *testing.T) *settlementRetryQueue {
	t.Helper()
	queue := &settlementRetryQueue{jobs: make(chan settlementRetryJob, 8), refunds: make(chan settlementRetryJob, 8), maxAttempts: 1}
	original := settlementRetries
	settlementRetries = queue
	t.Cleanup(func() { settlementRetries = original })
	return queue
}

// postChat sends one chat completions request through the real connection
// handler; see postJSON.
func postChat(t *testing.T, gateway *trustedrouter.Client, provider llm.Client, requestBody string) (int, string) {
	t.Helper()
	return postJSON(t, "/v1/chat/completions", gateway, provider, requestBody)
}

// postJSON sends one request through the real connection handler and returns
// the response status and body. It returns only after the handler has
// finished, so every billing call the request makes, including one made on the
// handler's way out, has been recorded.
func postJSON(t *testing.T, path string, gateway *trustedrouter.Client, provider llm.Client, requestBody string) (int, string) {
	t.Helper()
	serverConn, client := net.Pipe()
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		serveOne(context.Background(), serverConn, auth.New(nil), provider, nil, nil, gateway, nil)
	}()
	if _, err := fmt.Fprintf(client,
		"POST %s HTTP/1.1\r\nAuthorization: Bearer test-user-bearer\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s",
		path, len(requestBody), requestBody,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = client.Close()
	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the connection handler did not finish")
	}
	return response.StatusCode, string(body)
}

// A chat request that cannot be translated is answered before any authorize
// call: no hold exists, so none can be stranded however often the client
// retries. These exits used to authorize first and then return the 400 without
// a refund.
func TestChatRequestThatCannotBeTranslatedIsRejectedBeforeAuthorize(t *testing.T) {
	for _, tc := range []struct {
		name        string
		messages    string
		wantMessage string
	}{
		{"unknown role", `[{"role":"owner","content":"do something"},{"role":"user","content":"hi"}]`, "unsupported role"},
		{"no user or assistant turn", `[{"role":"system","content":"be terse"}]`, "messages must contain a user/assistant turn"},
		{"no turn after developer", `[{"role":"developer","content":"be terse"}]`, "messages must contain a user/assistant turn"},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", tc.name, stream), func(t *testing.T) {
				ledger := &holdLedger{}
				status, body := postChat(t, ledger.gateway(t), &panicStreamingLLM{t: t},
					fmt.Sprintf(`{"model":"openai/gpt-4o-mini","stream":%t,"messages":%s,"max_tokens":32}`, stream, tc.messages))
				if status != 400 {
					t.Fatalf("status = %d body=%s, want 400", status, body)
				}
				var decoded struct {
					Error struct {
						Message string `json:"message"`
					} `json:"error"`
				}
				if err := json.Unmarshal([]byte(body), &decoded); err != nil {
					t.Fatalf("decode error response: %v body=%s", err, body)
				}
				if decoded.Error.Message != tc.wantMessage {
					t.Fatalf("message = %q, want %q", decoded.Error.Message, tc.wantMessage)
				}
				// The rejected request is still attributed to its key, by the
				// metadata-only validation that creates no hold.
				if ledger.validated() != 1 {
					t.Fatalf("validations = %d, want the one metadata-only attribution", ledger.validated())
				}
				ledger.wantCalls(t, 0, 0, 0)
			})
		}
	}
}

// A request that works settles exactly once and is never refunded.
func TestChatRequestSettlesOnceAndIsNeverRefunded(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			ledger := &holdLedger{}
			status, body := postChat(t, ledger.gateway(t), &fakeStreamingLLM{},
				fmt.Sprintf(`{"model":"openai/gpt-4o-mini","stream":%t,"messages":[{"role":"user","content":"hi"}],"max_tokens":32}`, stream))
			if status != 200 || !strings.Contains(body, "Hello") {
				t.Fatalf("status = %d body=%s", status, body)
			}
			ledger.wantCalls(t, 1, 1, 0)
		})
	}
}

// goneClientWriter is a client connection that has gone away.
type goneClientWriter struct{}

func (goneClientWriter) Write([]byte) (int, error) {
	return 0, errors.New("client connection closed")
}

// panickingWriter stands in for an exit nobody wrote a terminal for: the
// handler leaves, by a panic, between its authorize and any settle or refund.
type panickingWriter struct{}

func (panickingWriter) Write([]byte) (int, error) { panic("handler bug after authorize") }

// holdTestRequestLogID has the shape of a real request audit id; the client
// leaves any other value out of the bodies it sends.
const holdTestRequestLogID = "rlog_00112233445566778899aabbccddeeff"

const messagesStreamBody = `{"model":"anthropic/claude-haiku-4.5","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"hi"}]}`

// The /v1/messages stream used to return without a terminal when the client
// went away before the stream head was written.
func TestMessagesStreamHeadWriteFailureRefundsTheHoldOnce(t *testing.T) {
	isolateSettlementRetries(t)
	ledger := &holdLedger{}
	ctx := trustedrouter.WithRequestLogID(context.Background(), holdTestRequestLogID)
	serveMessages(ctx, goneClientWriter{}, &fakeStreamingLLM{}, []byte(messagesStreamBody), ledger.gateway(t), nil, "test-key", "", holdTestRequestLogID, requestAttributionHeaders{})
	ledger.wantCalls(t, 1, 0, 1)
	refund := ledger.refunds[0]
	if refund["error_type"] != "client_write_failed" || refund["error_status"] != float64(499) {
		t.Fatalf("refund = %#v, want a 499 client_write_failed", refund)
	}
	if refund["authorization_id"] != "auth_1" || refund["gateway_request_id"] != holdTestRequestLogID {
		t.Fatalf("refund does not name the hold and the request: %#v", refund)
	}
}

// The synth final stream had the same exit: the client gone before the head.
func TestFusionFinalStreamHeadWriteFailureRefundsTheHoldOnce(t *testing.T) {
	isolateSettlementRetries(t)
	ledger := &holdLedger{}
	req := &types.OpenAIChatRequest{Model: trustedRouterSynthModel, MaxTokens: intPtrMainTest(4096), Stream: true, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}}}
	config := fusionConfig{AnalysisModels: []string{"model/a", "model/b"}, SelectionStrategy: defaultFusionSelectionStrategy}
	_ = serveFusionFinalStreaming(context.Background(), goneClientWriter{}, &fakeStreamingLLM{}, req, config, []string{"model/final"}, "analysis", nil, fusionCallResult{}, ledger.gateway(t), nil, "test-key", "idem-fusion", "rlog_fusion", nil)
	ledger.wantCalls(t, 1, 0, 1)
	if got := ledger.refundTypes(); got[0] != "client_write_failed" {
		t.Fatalf("refund types = %v", got)
	}
}

func TestMessagesRequestSettlesOnceAndIsNeverRefunded(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			ledger := &holdLedger{}
			var out bytes.Buffer
			body := strings.Replace(messagesStreamBody, `"stream":true`, fmt.Sprintf(`"stream":%t`, stream), 1)
			serveMessages(context.Background(), &out, &fakeStreamingLLM{}, []byte(body), ledger.gateway(t), nil, "test-key", "", "rlog_ok", requestAttributionHeaders{})
			if !strings.HasPrefix(out.String(), "HTTP/1.1 200 ") {
				t.Fatalf("response: %s", out.String())
			}
			ledger.wantCalls(t, 1, 1, 0)
		})
	}
}

// recoverPanic runs fn and reports whether it panicked.
func recoverPanic(fn func()) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	fn()
	return false
}

// An exit that sends no terminal of its own still closes the hold: the handler
// refunds it on the way out. A panic between the authorize and the first
// settle or refund is such an exit, and the only one a test can cause without
// changing the handler.
func TestHandlerExitWithoutATerminalRefundsTheHoldOnce(t *testing.T) {
	isolateSettlementRetries(t)
	t.Run("messages", func(t *testing.T) {
		ledger := &holdLedger{}
		gateway := ledger.gateway(t)
		if !recoverPanic(func() {
			serveMessages(context.Background(), panickingWriter{}, &fakeStreamingLLM{}, []byte(messagesStreamBody), gateway, nil, "test-key", "", "rlog_panic", requestAttributionHeaders{})
		}) {
			t.Fatal("the handler was expected to panic")
		}
		ledger.wantCalls(t, 1, 0, 1)
		if got := ledger.refundTypes(); got[0] != "gateway_exit_without_terminal" {
			t.Fatalf("refund types = %v", got)
		}
	})
	t.Run("embeddings", func(t *testing.T) {
		ledger := &holdLedger{}
		gateway := ledger.gateway(t)
		var out bytes.Buffer
		if !recoverPanic(func() {
			serveEmbeddings(context.Background(), &out, &panickingEmbeddingLLM{}, []byte(`{"model":"openai/text-embedding-3-large","input":"hi"}`), gateway, true, "test-key", nil, "idem-panic", requestAttributionHeaders{}, "rlog_panic")
		}) {
			t.Fatal("the handler was expected to panic")
		}
		ledger.wantCalls(t, 1, 0, 1)
		if got := ledger.refundTypes(); got[0] != "gateway_exit_without_terminal" {
			t.Fatalf("refund types = %v", got)
		}
	})
	t.Run("chat", func(t *testing.T) {
		ledger := &holdLedger{}
		gateway := ledger.gateway(t)
		requestBody := `{"model":"openai/gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}],"max_tokens":32}`
		conn := &panickingConn{scriptedConn: newScriptedConn(fmt.Sprintf(
			"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer test-user-bearer\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
			len(requestBody), requestBody,
		), nil)}
		if !recoverPanic(func() {
			serveOne(context.Background(), conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
		}) {
			t.Fatal("the handler was expected to panic")
		}
		ledger.wantCalls(t, 1, 0, 1)
		if got := ledger.refundTypes(); got[0] != "gateway_exit_without_terminal" {
			t.Fatalf("refund types = %v", got)
		}
	})
}

type panickingEmbeddingLLM struct{ fakeStreamingLLM }

func (*panickingEmbeddingLLM) InvokeEmbedding(context.Context, *types.EmbeddingRequest, ...llm.InvokeOptions) (*types.EmbeddingResponse, error) {
	panic("handler bug after authorize")
}

// panickingConn reads a scripted request and panics on the first response byte.
type panickingConn struct{ *scriptedConn }

func (*panickingConn) Write([]byte) (int, error) { panic("handler bug after authorize") }

func TestEmbeddingsRequestSettlesOnceAndIsNeverRefunded(t *testing.T) {
	ledger := &holdLedger{}
	var out bytes.Buffer
	serveEmbeddings(context.Background(), &out, &fakeEmbeddingLLM{}, []byte(`{"model":"openai/text-embedding-3-large","input":"hi"}`), ledger.gateway(t), true, "test-key", nil, "idem-ok", requestAttributionHeaders{}, "rlog_ok")
	if !strings.HasPrefix(out.String(), "HTTP/1.1 200 ") {
		t.Fatalf("response: %s", out.String())
	}
	ledger.wantCalls(t, 1, 1, 0)
}

// holdForTest places a real hold through the client, so it is tracked.
func holdForTest(t *testing.T, gateway *trustedrouter.Client) *trustedrouter.Authorization {
	t.Helper()
	authorization, err := gateway.AuthorizeWithRoute(context.Background(), "test-key",
		&types.OpenAIChatRequest{Model: "openai/gpt-4o-mini", Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}}},
		"chat.completions")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return authorization
}

// refundUnclosedHold refunds a hold nothing closed, once, and adds nothing to a
// hold that any path settled or refunded. After a settle that failed it stays
// silent too: the charge may have landed, or its retry is queued.
func TestRefundUnclosedHoldNeverAddsARefundToAClosedHold(t *testing.T) {
	isolateSettlementRetries(t)
	started := time.Now()
	settle := func(gateway *trustedrouter.Client, authorization *trustedrouter.Authorization) {
		_, _ = gateway.Settle(context.Background(), authorization, trustedrouter.Usage{RequestID: "req_1", InputTokens: 1, OutputTokens: 1})
	}
	for _, tc := range []struct {
		name         string
		settleStatus int
		before       func(*trustedrouter.Client, *trustedrouter.Authorization)
		wantSettles  int
		wantRefunds  []string
	}{
		{name: "nothing sent", wantRefunds: []string{"gateway_exit_without_terminal"}},
		{name: "settled", before: settle, wantSettles: 1},
		// 409 is not retried in-call, so the failure is immediate.
		{name: "settle failed", settleStatus: 409, before: settle, wantSettles: 1},
		{name: "refunded", wantRefunds: []string{"provider_error"}, before: func(gateway *trustedrouter.Client, authorization *trustedrouter.Authorization) {
			refundHold(context.Background(), gateway, authorization, 502, "provider_error", 0.1, nil)
		}},
		{name: "a copy was refunded", wantRefunds: []string{"client_write_failed"}, before: func(gateway *trustedrouter.Client, authorization *trustedrouter.Authorization) {
			selected := *authorization
			selected.Model = "selected"
			refundHold(context.Background(), gateway, &selected, 499, "client_write_failed", 0.1, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledger := &holdLedger{settleStatus: tc.settleStatus}
			gateway := ledger.gateway(t)
			authorization := holdForTest(t, gateway)
			if tc.before != nil {
				tc.before(gateway, authorization)
			}
			// Twice: a second pass must not refund again either.
			refundUnclosedHold(context.Background(), gateway, authorization, "chat.completions", started, nil)
			refundUnclosedHold(context.Background(), gateway, authorization, "chat.completions", started, nil)
			ledger.wantCalls(t, 1, tc.wantSettles, len(tc.wantRefunds))
			if got := ledger.refundTypes(); fmt.Sprint(got) != fmt.Sprint(tc.wantRefunds) {
				t.Fatalf("refund types = %v, want %v", got, tc.wantRefunds)
			}
		})
	}
	t.Run("not a hold this process placed", func(t *testing.T) {
		ledger := &holdLedger{}
		gateway := ledger.gateway(t)
		refundUnclosedHold(context.Background(), gateway, nil, "chat.completions", started, nil)
		refundUnclosedHold(context.Background(), gateway, &trustedrouter.Authorization{AuthorizationID: "auth_stored"}, "chat.completions", started, nil)
		refundUnclosedHold(context.Background(), nil, holdForTest(t, gateway), "chat.completions", started, nil)
		ledger.wantCalls(t, 1, 0, 0)
	})
}

// A refund that cannot be delivered is handed to the settlement retry queue,
// which sends the same refund again, instead of being dropped.
func TestRefundThatFailsIsQueuedForRetry(t *testing.T) {
	queue := isolateSettlementRetries(t)
	ledger := &holdLedger{refundStatus: 503}
	gateway := ledger.gateway(t)
	var out bytes.Buffer
	backend := &rejectedEmbeddingLLM{err: errors.New("provider failed")}
	ctx := trustedrouter.WithRequestLogID(context.Background(), holdTestRequestLogID)
	serveEmbeddings(ctx, &out, backend, []byte(`{"model":"openai/text-embedding-3-large","input":"hi"}`), gateway, true, "test-key", nil, "idem-retry", requestAttributionHeaders{}, holdTestRequestLogID)
	if !strings.HasPrefix(out.String(), "HTTP/1.1 502 ") {
		t.Fatalf("response: %s", out.String())
	}
	// One refund was attempted and failed; the handler's exit guard adds none.
	ledger.wantCalls(t, 1, 0, 1)
	if len(queue.refunds) != 1 || len(queue.jobs) != 0 {
		t.Fatalf("queued refunds = %d, queued settles = %d, want the failed refund in the refund queue", len(queue.refunds), len(queue.jobs))
	}
	job := <-queue.refunds
	if job.kind != "refund" || job.frozen == nil {
		t.Fatalf("queued job is not a frozen refund: kind=%q frozen=%v", job.kind, job.frozen)
	}

	// The control plane recovers; the queued retry delivers the same refund.
	ledger.mu.Lock()
	ledger.refundStatus = 0
	ledger.mu.Unlock()
	queue.process(context.Background(), job)
	ledger.wantCalls(t, 1, 0, 2)
	first, retried := ledger.refunds[0], ledger.refunds[1]
	for _, field := range []string{"authorization_id", "error_status", "error_type", "gateway_request_id"} {
		if first[field] == nil || first[field] != retried[field] {
			t.Fatalf("retried refund %s = %v, first attempt sent %v", field, retried[field], first[field])
		}
	}
	if len(queue.jobs)+len(queue.refunds) != 0 {
		t.Fatalf("queued retries after success = %d, want 0", len(queue.jobs)+len(queue.refunds))
	}
}

// The exit refund is claimed before it is sent, so guards racing each other
// for one authorization send one refund between them. Run under the race
// detector.
func TestConcurrentExitGuardsSendOneRefund(t *testing.T) {
	isolateSettlementRetries(t)
	ledger := &holdLedger{}
	gateway := ledger.gateway(t)
	authorization := holdForTest(t, gateway)
	started := time.Now()
	const guards = 32
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	for range guards {
		ready.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			refundUnclosedHold(context.Background(), gateway, authorization, "chat.completions", started, nil)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	ledger.wantCalls(t, 1, 0, 1)
}

// The check before the authorize covers the Responses handler too: a request
// that parses and converts but has nothing to translate is answered with no
// authorize call.
func TestResponsesRequestThatCannotBeTranslatedIsRejectedBeforeAuthorize(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			ledger := &holdLedger{}
			status, body := postJSON(t, "/v1/responses", ledger.gateway(t), &panicStreamingLLM{t: t},
				fmt.Sprintf(`{"model":"openai/gpt-4o-mini","stream":%t,"input":[{"role":"developer","content":"only instructions"}]}`, stream))
			if status != 400 || !strings.Contains(body, "messages must contain a user/assistant turn") {
				t.Fatalf("status = %d body=%s", status, body)
			}
			if ledger.validated() != 1 {
				t.Fatalf("validations = %d, want the one metadata-only attribution", ledger.validated())
			}
			ledger.wantCalls(t, 0, 0, 0)
		})
	}
}

// The check before the authorize is on the plain chat and responses path. The
// orchestration handlers run ahead of it, authorize their inner calls and
// translate afterwards, so a request that cannot be translated still places
// holds there. Each one is refunded: nothing is stranded and nothing settles.
func TestSynthRequestThatCannotBeTranslatedRefundsEveryHoldItPlaces(t *testing.T) {
	isolateSettlementRetries(t)
	ledger := &holdLedger{}
	status, body := postChat(t, ledger.gateway(t), &fusionEchoLLM{},
		`{"model":"trustedrouter/fusion","stream":false,"messages":[{"role":"owner","content":"do something"},{"role":"user","content":"hi"}],`+
			`"tools":[{"type":"trustedrouter:fusion","parameters":{"analysis_models":["google/gemini-3-flash-preview","moonshotai/kimi-k2.7-code"],"model":"z-ai/glm-5.2","max_completion_tokens":64}}],"max_tokens":32}`)
	if status < 400 || status >= 500 {
		t.Fatalf("status = %d body=%s, want a client error", status, body)
	}
	authorizes, settles, refunds := ledger.calls()
	if authorizes == 0 {
		t.Fatal("no hold was placed: this path now checks before it authorizes, and the test and its comment are out of date")
	}
	if settles != 0 || refunds != authorizes {
		t.Fatalf("authorize=%d settle=%d refund=%d (%v), want every hold refunded and none settled", authorizes, settles, refunds, ledger.refundTypes())
	}
}

// A response that cannot be encoded used to return a 500 with the hold still
// open. No client or provider can cause this: the value below is one JSON
// cannot carry, set directly on the request struct. The chat and messages
// encoders take nothing a test can set that way, so their two exits are not
// driven; the exit guard tests above stand in for them.
func TestResponsesEncodeErrorRefundsTheHoldOnce(t *testing.T) {
	isolateSettlementRetries(t)
	ledger := &holdLedger{}
	gateway := ledger.gateway(t)
	authorization := holdForTest(t, gateway)
	started := time.Now()
	maxTokens := 32
	req := &types.OpenAIChatRequest{
		Model: "openai/gpt-4o-mini", MaxTokens: &maxTokens,
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}},
		Response: &types.ResponseRequestMeta{ToolChoice: math.Inf(1)},
	}
	var out bytes.Buffer
	ctx := trustedrouter.WithRequestLogID(context.Background(), holdTestRequestLogID)
	serveResponsesNonStreaming(ctx, &out, &fakeStreamingLLM{}, req, &types.AnthropicMessagesRequest{},
		[]llm.InvokeOptions{{Model: req.Model, Provider: "openai", EndpointID: "e@openai/prepaid"}},
		gateway, authorization, nil, started, nil, holdTestRequestLogID, req.Model)
	if !strings.HasPrefix(out.String(), "HTTP/1.1 500 ") || !strings.Contains(out.String(), "responses encoding error") {
		t.Fatalf("response: %s", out.String())
	}
	// The handler's exit guard runs after it; it must add nothing.
	refundUnclosedHold(ctx, gateway, authorization, "responses", started, nil)
	ledger.wantCalls(t, 1, 0, 1)
	refund := ledger.refunds[0]
	if refund["error_type"] != "response_encoding_error" || refund["error_status"] != float64(500) || refund["gateway_request_id"] != holdTestRequestLogID {
		t.Fatalf("refund = %#v", refund)
	}
}
