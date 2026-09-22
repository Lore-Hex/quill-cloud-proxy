package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Every authorization must end in exactly one settle or one refund, whatever
// happens in between, and a failure after a provider has run must tell the
// client not to retry. These tests drive the failures that did neither.

// faultyControlPlane is a control plane whose calls can be made to fail. A zero
// status means success. Calls are counted from 1.
type faultyControlPlane struct {
	authorizeStatus func(call int) int
	settleStatus    func(call int) int
	hosted          bool
	// nativeCandidates, when set, is the route_candidates JSON array a native
	// authorization returns, so a test can exercise failover between hosts.
	nativeCandidates string
	log              controlPlaneLog
}

func (f *faultyControlPlane) serve(t *testing.T) *trustedrouter.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		raw, _ := io.ReadAll(request.Body)
		if bytes.Contains(raw, []byte("PRIVATE-STATE")) {
			t.Fatalf("control plane received decision content on %s", request.URL.Path)
		}
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		fail := func(status int) bool {
			if status == 0 {
				return false
			}
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `{"error":{"message":"control plane says %d","type":"test"}}`, status)
			return true
		}
		switch request.URL.Path {
		case "/internal/gateway/authorize":
			f.log.authorize = append(f.log.authorize, body)
			if f.authorizeStatus != nil && fail(f.authorizeStatus(len(f.log.authorize))) {
				return
			}
			if f.hosted {
				_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_h","workspace_id":"ws_1","api_key_hash":"key_1",
				 "model":"typesafe-ai/jev","endpoint_id":"typesafe-ai/jev@typesafe/prepaid","provider":"typesafe","upstream_model":"jev-latest",
				 "usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[
				  {"endpoint_id":"typesafe-ai/jev@typesafe/prepaid","model":"typesafe-ai/jev","upstream_model":"jev-latest","provider":"typesafe","usage_type":"Credits"},
				  {"endpoint_id":"typesafe-ai/jev@vercel-ai-gateway/prepaid","model":"typesafe-ai/jev","upstream_model":"typesafe-ai/jev","provider":"vercel-ai-gateway","usage_type":"Credits"}]}}`)
				return
			}
			candidates := f.nativeCandidates
			if candidates == "" {
				candidates = "[]"
			}
			_, _ = fmt.Fprintf(w, `{"data":{"authorization_id":"auth_%d","workspace_id":"ws_1","api_key_hash":"key_1","model":%q,"endpoint_id":"e@p/prepaid","provider":"cerebras","upstream_model":"gpt-oss-120b","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":%s}}`,
				len(f.log.authorize), body["model"], candidates)
		case "/internal/gateway/settle":
			f.log.settle = append(f.log.settle, body)
			if f.settleStatus != nil && fail(f.settleStatus(len(f.log.settle))) {
				return
			}
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_1","cost_microdollars":20,"model":"m","provider":"p","region":"us-central1"}}`)
		case "/internal/gateway/refund":
			f.log.refund++
			_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", request.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return trustedrouter.New(server.URL, "internal-token", server.Client())
}

const hostedBody = `{"model":"typesafe-ai/jev",%s"state":"` + privateState + `","questions":{
  "refund":{"type":"boolean","instructions":"Is a refund requested?"},
  "route":{"type":"choice","instructions":"Route it.","criteria":{"billing":"charges","shipping":"delivery"}}}}`

const nativeBody = `{"model":"openai/gpt-oss-20b","state":"` + privateState + `","questions":{
  "refund":{"type":"boolean","instructions":"Is a refund requested?"},
  "route":{"type":"choice","instructions":"Route it.","criteria":{"billing":"charges","shipping":"delivery"}}}}`

// rawDecide returns the status and the raw HTTP response, headers included.
func rawDecide(ctx context.Context, backend llm.Client, gateway *trustedrouter.Client, body string) (int, string) {
	var out bytes.Buffer
	serveDecide(ctx, &out, backend, []byte(body), gateway, true, "sk-tr-test-bearer", nil, "idem-m", requestAttributionHeaders{}, "log-m")
	raw := out.String()
	status := 0
	_, _ = fmt.Sscanf(strings.Fields(strings.SplitN(raw, "\r\n", 2)[0])[1], "%d", &status)
	return status, raw
}

func saysDoNotRetry(raw string) bool {
	head := strings.ToLower(strings.SplitN(raw, "\r\n\r\n", 2)[0])
	return strings.Contains(head, shouldRetryHeader+": false")
}

// cancellingDecider cancels the REQUEST's context while the vendor call is in
// flight -- what a draining gateway does to its in-flight requests -- and then
// either fails or answers.
type cancellingDecider struct {
	cancel  context.CancelFunc
	answers map[string]decide.Answer
	tokens  int
}

func (c *cancellingDecider) InvokeStreaming(context.Context, *types.OpenAIChatRequest, *types.AnthropicMessagesRequest, io.Writer, ...llm.InvokeOptions) error {
	panic("the hosted decision path must never call the chat client")
}

func (c *cancellingDecider) InvokeDecide(context.Context, *llm.DecideRequest, ...llm.InvokeOptions) (*llm.DecideResponse, error) {
	if c.cancel != nil {
		c.cancel()
	}
	if c.answers == nil {
		return nil, &llm.DecideError{Provider: "typesafe", Class: llm.DecideErrCanceled}
	}
	return &llm.DecideResponse{Answers: c.answers, InputTokens: c.tokens}, nil
}

func TestHostedDecideRefundsAfterTheRequestWasCancelled(t *testing.T) {
	plane := &faultyControlPlane{hosted: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	status, _ := rawDecide(ctx, &cancellingDecider{cancel: cancel}, plane.serve(t), fmt.Sprintf(hostedBody, ""))
	if status != 502 {
		t.Fatalf("status %d, want 502", status)
	}
	// A refund sent on the cancelled context never leaves the process: one
	// authorization, no settle, no refund, a hold stranded until it is reaped.
	if len(plane.log.authorize) != 1 || plane.log.refund != 1 || len(plane.log.settle) != 0 {
		t.Fatalf("authorize=%d refund=%d settle=%d, want 1/1/0", len(plane.log.authorize), plane.log.refund, len(plane.log.settle))
	}
}

func TestHostedDecideSettlesAnAnswerItAlreadyPaidFor(t *testing.T) {
	plane := &faultyControlPlane{hosted: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	status, _ := rawDecide(ctx, &cancellingDecider{cancel: cancel, answers: hostedAnswers(), tokens: 444}, plane.serve(t), fmt.Sprintf(hostedBody, ""))
	if status != 200 {
		t.Fatalf("status %d, want 200", status)
	}
	if len(plane.log.settle) != 1 || plane.log.refund != 0 {
		t.Fatalf("settle=%d refund=%d, want 1/0: the vendor ran and was never billed", len(plane.log.settle), plane.log.refund)
	}
}

func TestHostedDecideSettleFailureTellsTheClientNotToRetry(t *testing.T) {
	plane := &faultyControlPlane{hosted: true, settleStatus: func(int) int { return 503 }}
	status, raw := rawDecide(context.Background(), &cancellingDecider{answers: hostedAnswers(), tokens: 444}, plane.serve(t), fmt.Sprintf(hostedBody, ""))
	if status != 502 || !saysDoNotRetry(raw) {
		t.Fatalf("status %d, do-not-retry=%v: the vendor already ran", status, saysDoNotRetry(raw))
	}
}

func TestHostedDecideBillsAtMostWhatTheRequestCouldHaveCost(t *testing.T) {
	plane := &faultyControlPlane{hosted: true}
	var status int
	stderr := captureStderr(t, func() {
		status, _ = rawDecide(context.Background(), &cancellingDecider{answers: hostedAnswers(), tokens: math.MaxInt64}, plane.serve(t), fmt.Sprintf(hostedBody, ""))
	})
	if status != 200 || len(plane.log.settle) != 1 {
		t.Fatalf("status %d settle=%d", status, len(plane.log.settle))
	}
	billed, _ := plane.log.settle[0]["actual_input_tokens"].(float64)
	// A token is at least a byte: nothing this request sent could exceed its
	// own length plus the vendor's template.
	if ceiling := float64(len(fmt.Sprintf(hostedBody, "")) + hostedTemplateTokenAllowance); billed <= 0 || billed > ceiling {
		t.Fatalf("billed %v input tokens for a %d-byte request (ceiling %v)", billed, len(hostedBody), ceiling)
	}
	if !strings.Contains(stderr, "enclave.decide_usage_clamped") {
		t.Errorf("a clamp that leaves no trace cannot be investigated:\n%s", stderr)
	}
	// An honest count is billed as reported.
	honest := &faultyControlPlane{hosted: true}
	rawDecide(context.Background(), &cancellingDecider{answers: hostedAnswers(), tokens: 61}, honest.serve(t), fmt.Sprintf(hostedBody, ""))
	if got, _ := honest.log.settle[0]["actual_input_tokens"].(float64); got != 61 {
		t.Fatalf("an honest count of 61 was billed as %v", got)
	}
}

func TestHostedDecideLogsNothingAVendorSaid(t *testing.T) {
	// A foreign error whose text quotes the caller's state. The shared
	// errorClass() falls back to the first 80 characters of the message.
	leaky := fmt.Errorf("vendor rejected state: %s", privateState)
	backend := &hostScriptedDecider{failing: map[string]error{"typesafe": leaky, "vercel-ai-gateway": leaky}}
	plane := &faultyControlPlane{hosted: true}
	stderr := captureStderr(t, func() {
		rawDecide(context.Background(), backend, plane.serve(t), fmt.Sprintf(hostedBody, ""))
	})
	if strings.Contains(stderr, "PRIVATE-STATE") || strings.Contains(stderr, "vendor rejected") {
		t.Fatalf("stderr carries what the vendor said:\n%s", stderr)
	}
	if got := strings.Count(stderr, `error_class="unknown"`); got != 2 {
		t.Fatalf("want both hosts logged as unknown, got %d:\n%s", got, stderr)
	}
}

func TestHostedDecideTreatsNullFalseAndEmptyAsUnset(t *testing.T) {
	unset := `"stream":false,"reasoning":null,"reasoning_effort":"","max_tokens":null,"provider":null,`
	plane := &faultyControlPlane{hosted: true}
	if status, raw := rawDecide(context.Background(), &cancellingDecider{answers: hostedAnswers(), tokens: 61}, plane.serve(t), fmt.Sprintf(hostedBody, unset)); status != 200 {
		t.Fatalf("an SDK that serializes its defaults got %d: %s", status, raw)
	}
	// Asking for something is still refused, and the SAME parameter is named
	// every time (this used to range over a map).
	both := `"max_tokens":64,"reasoning":{"effort":"high"},`
	for i := 0; i < 25; i++ {
		status, raw := rawDecide(context.Background(), &cancellingDecider{answers: hostedAnswers()}, (&faultyControlPlane{hosted: true}).serve(t), fmt.Sprintf(hostedBody, both))
		if status != 400 || !strings.Contains(raw, `"param":"reasoning"`) {
			t.Fatalf("run %d: status %d, body %s", i, status, raw)
		}
	}
}

// usageScriptedLLM is scriptedLLM with the reported input tokens under test
// control, and an optional failure instead of a reply.
type usageScriptedLLM struct {
	replies     []string
	inputTokens int
	fail        error
	calls       int
}

func (s *usageScriptedLLM) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	s.calls++
	if s.fail != nil {
		return s.fail
	}
	text, _ := json.Marshal(s.replies[s.calls-1])
	_, err := fmt.Fprintf(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"m","stop_reason":null,"usage":{"input_tokens":%d,"cache_read_input_tokens":400,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%s}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":60}}

event: message_stop
data: {"type":"message_stop"}

`, s.inputTokens, text)
	return err
}

func TestNativeDecideTellsTheClientNotToRetryOnceAProviderRan(t *testing.T) {
	// Attempt 1 is billed and fails verification; attempt 2 cannot authorize.
	// With every input token read from cache the count is 0, which used to be
	// taken to mean "nothing was spent".
	plane := &faultyControlPlane{authorizeStatus: func(call int) int {
		if call == 2 {
			return 402
		}
		return 0
	}}
	backend := &usageScriptedLLM{replies: []string{`{"q0":"not a number","q1":{"q1_o0":1}}`}, inputTokens: 0}
	status, raw := rawDecide(context.Background(), backend, plane.serve(t), nativeBody)
	if status != 402 || !saysDoNotRetry(raw) {
		t.Fatalf("status %d, do-not-retry=%v, settles=%d\n%s", status, saysDoNotRetry(raw), len(plane.log.settle), raw)
	}

	// The provider answered and SETTLEMENT failed: no usage came back at all.
	plane = &faultyControlPlane{settleStatus: func(int) int { return 503 }}
	backend = &usageScriptedLLM{replies: []string{goodNative}, inputTokens: 400}
	status, raw = rawDecide(context.Background(), backend, plane.serve(t), nativeBody)
	if status < 500 || !saysDoNotRetry(raw) {
		t.Fatalf("status %d, do-not-retry=%v\n%s", status, saysDoNotRetry(raw), raw)
	}

	// Nothing ran: a retry is safe and must not be discouraged.
	plane = &faultyControlPlane{authorizeStatus: func(int) int { return 402 }}
	status, raw = rawDecide(context.Background(), &usageScriptedLLM{}, plane.serve(t), nativeBody)
	if status != 402 || saysDoNotRetry(raw) {
		t.Fatalf("status %d, do-not-retry=%v: no provider ran", status, saysDoNotRetry(raw))
	}
}

func TestNativeDecideNeverRelaysAProvidersAuthFailure(t *testing.T) {
	for _, vendorStatus := range []int{401, 403} {
		plane := &faultyControlPlane{}
		backend := &usageScriptedLLM{fail: fmt.Errorf("llm/upstream: http %d: invalid api key", vendorStatus)}
		status, raw := rawDecide(context.Background(), backend, plane.serve(t), nativeBody)
		// OUR provider key is bad. A 401 would tell the caller theirs is.
		if status != 502 {
			t.Fatalf("vendor %d reached the caller as %d: %s", vendorStatus, status, raw)
		}
		// Both attempts fail the same way; each authorization is refunded.
		if len(plane.log.authorize) != nativeDecisionAttempts || plane.log.refund != len(plane.log.authorize) || len(plane.log.settle) != 0 {
			t.Fatalf("vendor %d: authorize=%d refund=%d settle=%d, want every authorization refunded", vendorStatus, len(plane.log.authorize), plane.log.refund, len(plane.log.settle))
		}
	}
	// The control plane's own 401 IS about the caller's key, and is relayed.
	plane := &faultyControlPlane{authorizeStatus: func(int) int { return 401 }}
	if status, _ := rawDecide(context.Background(), &usageScriptedLLM{}, plane.serve(t), nativeBody); status != 401 {
		t.Fatalf("control-plane 401 reached the caller as %d", status)
	}
}

// silentLLM is a provider that RAN and said nothing a text-delta observer can
// see: usage, a stop, no content -- a filtered completion, for instance.
type silentLLM struct{}

func (silentLLM) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	_, err := fmt.Fprint(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"m","stop_reason":null,"usage":{"input_tokens":400,"output_tokens":0}}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":0}}

event: message_stop
data: {"type":"message_stop"}

`)
	return err
}

func TestNativeDecideRefundsAProviderThatProducedNoGeneration(t *testing.T) {
	// A finish with no text at all is the provider failing (a filtered or
	// errored completion closed with a synthetic stop), not the model answering
	// badly. It used to be SETTLED: billed, retried, billed again, and then the
	// caller was told not to retry. Now each such attempt is refunded.
	plane := &faultyControlPlane{}
	status, raw := rawDecide(context.Background(), silentLLM{}, plane.serve(t), nativeBody)
	if status != 502 || saysDoNotRetry(raw) {
		t.Fatalf("status %d, do-not-retry=%v: nothing was generated or billed\n%s", status, saysDoNotRetry(raw), raw)
	}
	if len(plane.log.authorize) != 2 || plane.log.refund != 2 || len(plane.log.settle) != 0 {
		t.Fatalf("authorize=%d refund=%d settle=%d, want 2/2/0", len(plane.log.authorize), plane.log.refund, len(plane.log.settle))
	}
}

// truncatedThenGood dies mid-answer on its first call (a text delta, then the
// stream simply ends: no stop reason, no message_stop) and answers on the next.
type truncatedThenGood struct{ calls int }

func (b *truncatedThenGood) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	b.calls++
	if b.calls == 1 {
		_, err := fmt.Fprint(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"m","stop_reason":null,"usage":{"input_tokens":400,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"{\"q0\":"}}

event: error
data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}

`)
		return err
	}
	return (&usageScriptedLLM{replies: []string{goodNative}, inputTokens: 400}).InvokeStreaming(context.Background(), nil, nil, out)
}

func TestNativeDecideRefundsAStreamThatDiedMidAnswerAndTriesAgain(t *testing.T) {
	plane := &faultyControlPlane{}
	backend := &truncatedThenGood{}
	status, raw := rawDecide(context.Background(), backend, plane.serve(t), nativeBody)
	if status != 200 {
		t.Fatalf("status %d\n%s", status, raw)
	}
	// The dead stream is refunded, never settled; only the answer is billed.
	if backend.calls != 2 || plane.log.refund != 1 || len(plane.log.settle) != 1 {
		t.Fatalf("calls=%d refund=%d settle=%d, want 2/1/1", backend.calls, plane.log.refund, len(plane.log.settle))
	}
	var payload struct {
		Usage decideUsage `json:"usage"`
	}
	_ = json.Unmarshal([]byte(strings.SplitN(raw, "\r\n\r\n", 2)[1]), &payload)
	if payload.Usage.InputTokens != 400 {
		t.Fatalf("usage counts the refunded attempt: %+v", payload.Usage)
	}
	var response map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(raw, "\r\n\r\n", 2)[1]), &response); err != nil {
		t.Fatal(err)
	}
	assertDecideRouting(t, response, `{"selected_model":"m","selected_provider":"p","selected_endpoint":"e@p/prepaid","fallback_candidate_count":1,"upstream_attempt_count":2,"fallback_attempt_count":0}`)
}

// cancelledMidCall cancels the request and fails the way a provider client
// does when its context goes away.
type cancelledMidCall struct{ cancel context.CancelFunc }

func (c cancelledMidCall) InvokeStreaming(ctx context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, _ io.Writer, _ ...llm.InvokeOptions) error {
	c.cancel()
	return context.Canceled
}

func TestNativeDecideRefundsAfterTheRequestWasCancelled(t *testing.T) {
	// The shared call refunded on the request's own context, so once that was
	// cancelled the refund never left: a hold stranded until it is reaped.
	plane := &faultyControlPlane{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rawDecide(ctx, cancelledMidCall{cancel}, plane.serve(t), nativeBody)
	if len(plane.log.authorize) != 1 || plane.log.refund != 1 || len(plane.log.settle) != 0 {
		t.Fatalf("authorize=%d refund=%d settle=%d, want 1/1/0", len(plane.log.authorize), plane.log.refund, len(plane.log.settle))
	}
}

func TestHostedDecideAnInvalidAnswerTellsTheClientNotToRetry(t *testing.T) {
	// The vendor ran and was paid; asking again buys the same invalid answer.
	p, choice := 0.97, "billing"
	invalid := map[string]decide.Answer{
		"refund": {Type: decide.TypeBoolean, Probability: &p},
		"route":  {Type: decide.TypeChoice, Choice: &choice, Probabilities: map[string]float64{"billing": 0.2, "shipping": 0.2}},
	}
	plane := &faultyControlPlane{hosted: true}
	status, raw := rawDecide(context.Background(), &cancellingDecider{answers: invalid, tokens: 61}, plane.serve(t), fmt.Sprintf(hostedBody, ""))
	if status != 502 || !saysDoNotRetry(raw) {
		t.Fatalf("status %d, do-not-retry=%v\n%s", status, saysDoNotRetry(raw), raw)
	}
	if plane.log.refund != 1 || len(plane.log.settle) != 0 {
		t.Fatalf("refund=%d settle=%d, want the caller refunded", plane.log.refund, len(plane.log.settle))
	}
}

// refusesThenCancels is the first host refusing the request as the gateway
// starts to drain: the second host is never asked.
type refusesThenCancels struct {
	cancel context.CancelFunc
	called int
}

func (r *refusesThenCancels) InvokeStreaming(context.Context, *types.OpenAIChatRequest, *types.AnthropicMessagesRequest, io.Writer, ...llm.InvokeOptions) error {
	panic("the hosted decision path must never call the chat client")
}

func (r *refusesThenCancels) InvokeDecide(context.Context, *llm.DecideRequest, ...llm.InvokeOptions) (*llm.DecideResponse, error) {
	r.called++
	r.cancel()
	return nil, &llm.DecideError{Provider: "typesafe", Class: llm.DecideErrHTTP, Status: 422}
}

func TestHostedDecideAnInterruptedFailoverIsNotTheCallersFault(t *testing.T) {
	plane := &faultyControlPlane{hosted: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := &refusesThenCancels{cancel: cancel}
	status, raw := rawDecide(ctx, backend, plane.serve(t), fmt.Sprintf(hostedBody, ""))
	// One host said 422 and the other was never asked. "Every host refused it"
	// is not something anyone knows, and a 400 would make a drain permanent.
	if backend.called != 1 || status != 502 {
		t.Fatalf("hosts asked=%d status=%d, want 1 and 502\n%s", backend.called, status, raw)
	}
	if plane.log.refund != 1 {
		t.Fatalf("refund=%d, want 1", plane.log.refund)
	}
}

func TestHostedDecideNamesTheMalformedReasoningField(t *testing.T) {
	plane := &faultyControlPlane{hosted: true}
	body := fmt.Sprintf(hostedBody, `"reasoning":{"enabled":false,"zeta":1,"alpha":1},`)
	status, raw := rawDecide(context.Background(), &cancellingDecider{answers: hostedAnswers()}, plane.serve(t), body)
	if status != 400 || !strings.Contains(raw, `"param":"reasoning.alpha"`) {
		t.Fatalf("status %d: %s", status, raw)
	}
	if len(plane.log.authorize) != 0 {
		t.Fatal("a malformed request was authorized")
	}
}

func TestDecideKeepsTheControlPlanesRetryAfter(t *testing.T) {
	// A 429 for a per-key window says when the window resets. Dropping the
	// header leaves an agent to back off blindly.
	limited := func(hosted bool) *trustedrouter.Client {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(429)
			_, _ = fmt.Fprint(w, `{"error":{"message":"key window limit reached","type":"rate_limit"}}`)
		}))
		t.Cleanup(server.Close)
		return trustedrouter.New(server.URL, "internal-token", server.Client())
	}
	for label, body := range map[string]string{"native": nativeBody, "hosted": fmt.Sprintf(hostedBody, "")} {
		status, raw := rawDecide(context.Background(), &cancellingDecider{answers: hostedAnswers()}, limited(label == "hosted"), body)
		head := strings.ToLower(strings.SplitN(raw, "\r\n\r\n", 2)[0])
		if status != 429 || !strings.Contains(head, "retry-after: 120") {
			t.Errorf("%s: status %d, headers:\n%s", label, status, head)
		}
		if saysDoNotRetry(raw) {
			t.Errorf("%s: nothing ran, a retry after the window is exactly right", label)
		}
	}
}

func TestNativeDecideLogsNothingAProviderSaid(t *testing.T) {
	// The shared provider path logs errorClass(err), which fell back to the
	// first 80 characters of the message.
	plane := &faultyControlPlane{}
	backend := &usageScriptedLLM{fail: fmt.Errorf("vendor rejected state: %s", privateState)}
	stderr := captureStderr(t, func() {
		rawDecide(context.Background(), backend, plane.serve(t), nativeBody)
	})
	if strings.Contains(stderr, "PRIVATE-STATE") || strings.Contains(stderr, "vendor rejected") {
		t.Fatalf("stderr carries what the provider said:\n%s", stderr)
	}
}

func TestHostedDecideAcceptsEveryWayOfNotAskingToReason(t *testing.T) {
	for _, unset := range []string{`"reasoning":false,`, `"reasoning_effort":"none",`, `"reasoning":{"enabled":false},`} {
		plane := &faultyControlPlane{hosted: true}
		if status, raw := rawDecide(context.Background(), &cancellingDecider{answers: hostedAnswers(), tokens: 61}, plane.serve(t), fmt.Sprintf(hostedBody, unset)); status != 200 {
			t.Errorf("%s: %d %s", unset, status, raw)
		}
	}
	// Malformed is not "unset": it is refused, never silently dropped.
	plane := &faultyControlPlane{hosted: true}
	if status, _ := rawDecide(context.Background(), &cancellingDecider{answers: hostedAnswers()}, plane.serve(t), fmt.Sprintf(hostedBody, `"reasoning_effort":"banana",`)); status != 400 {
		t.Errorf("a malformed effort on a hosted model: %d, want 400", status)
	}
}

// keepaliveThenFail is a provider that sends bytes and then dies before any
// generation: an SSE comment, then a dropped connection.
type keepaliveThenFail struct{}

func (keepaliveThenFail) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	_, _ = io.WriteString(out, ": keepalive\n\n")
	return io.ErrUnexpectedEOF
}

func TestNativeDecideInvitesARetryWhenNoResultWasEverProduced(t *testing.T) {
	// Bytes are not a result. A version that watched the provider's writes sent
	// x-should-retry: false here, telling the client not to retry a call that
	// produced nothing and was refunded.
	plane := &faultyControlPlane{}
	status, raw := rawDecide(context.Background(), keepaliveThenFail{}, plane.serve(t), nativeBody)
	if status != 502 || saysDoNotRetry(raw) {
		t.Fatalf("status %d, do-not-retry=%v: nothing was produced, a retry is right\n%s", status, saysDoNotRetry(raw), raw)
	}
	if len(plane.log.authorize) != nativeDecisionAttempts || plane.log.refund != len(plane.log.authorize) || len(plane.log.settle) != 0 {
		t.Fatalf("authorize=%d refund=%d settle=%d, want every authorization refunded", len(plane.log.authorize), plane.log.refund, len(plane.log.settle))
	}
}

func TestHostedDecideSettlementFailureKeepsRetryAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/settle") {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(429)
			_, _ = fmt.Fprint(w, `{"error":{"message":"settlement is rate limited","type":"rate_limit"}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_h","workspace_id":"ws_1","api_key_hash":"key_1",
		 "model":"typesafe-ai/jev","endpoint_id":"typesafe-ai/jev@typesafe/prepaid","provider":"typesafe","upstream_model":"jev-latest",
		 "usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
	}))
	t.Cleanup(server.Close)
	gateway := trustedrouter.New(server.URL, "internal-token", server.Client())
	status, raw := rawDecide(context.Background(), &cancellingDecider{answers: hostedAnswers(), tokens: 61}, gateway, fmt.Sprintf(hostedBody, ""))
	head := strings.ToLower(strings.SplitN(raw, "\r\n\r\n", 2)[0])
	// The vendor ran, so: do not retry blindly -- and here is when settlement
	// will take it.
	if status != 502 || !saysDoNotRetry(raw) || !strings.Contains(head, "retry-after: 120") {
		t.Fatalf("status %d, headers:\n%s", status, head)
	}
}

func TestHostedDecideARequestEveryHostRefusesIsTheCallers400(t *testing.T) {
	refused := func(status int) error {
		return &llm.DecideError{Provider: "p", Class: llm.DecideErrHTTP, Status: status}
	}
	for label, tc := range map[string]struct {
		failing map[string]error
		want    int
	}{
		"both refuse it as invalid":       {map[string]error{"typesafe": refused(422), "vercel-ai-gateway": refused(400)}, 400},
		"too large for both":              {map[string]error{"typesafe": refused(413), "vercel-ai-gateway": refused(413)}, 400},
		"one refuses, one is down":        {map[string]error{"typesafe": refused(422), "vercel-ai-gateway": refused(503)}, 502},
		"our key is bad (never a 4xx)":    {map[string]error{"typesafe": refused(401), "vercel-ai-gateway": refused(403)}, 502},
		"rate limited everywhere":         {map[string]error{"typesafe": refused(429), "vercel-ai-gateway": refused(429)}, 502},
		"one refuses, one never answered": {map[string]error{"typesafe": refused(422), "vercel-ai-gateway": &llm.DecideError{Provider: "p", Class: llm.DecideErrTransport}}, 502},
	} {
		plane := &faultyControlPlane{hosted: true}
		status, raw := rawDecide(context.Background(), &hostScriptedDecider{failing: tc.failing}, plane.serve(t), fmt.Sprintf(hostedBody, ""))
		if status != tc.want {
			t.Errorf("%s: status %d, want %d\n%s", label, status, tc.want, raw)
		}
		if plane.log.refund != 1 || len(plane.log.settle) != 0 {
			t.Errorf("%s: refund=%d settle=%d, want 1/0", label, plane.log.refund, len(plane.log.settle))
		}
		if saysDoNotRetry(raw) {
			t.Errorf("%s: no answer was produced, so nothing says do-not-retry", label)
		}
	}
}

// errorsMidStreamThenAnswers writes an error event and FAILS on its first call,
// as a provider client does when the host dies mid-answer, and answers on the
// next call.
type errorsMidStreamThenAnswers struct{ calls int }

func (b *errorsMidStreamThenAnswers) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	b.calls++
	if b.calls == 1 {
		_, _ = io.WriteString(out, "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n")
		return fmt.Errorf("llm/upstream: http 529: overloaded")
	}
	return (&usageScriptedLLM{replies: []string{goodNative}, inputTokens: 400}).InvokeStreaming(context.Background(), nil, nil, out)
}

func TestNativeDecideGivesAFailedProviderTheOtherAttempt(t *testing.T) {
	// The provider loop commits to a host at its first byte, so a host that dies
	// AFTER that cannot fail over inside the attempt. It is refunded, nothing
	// has reached the caller, and the second attempt is the failover. It used to
	// end the request: only a stream that ended QUIETLY got the second attempt.
	plane := &faultyControlPlane{}
	backend := &errorsMidStreamThenAnswers{}
	status, raw := rawDecide(context.Background(), backend, plane.serve(t), nativeBody)
	if status != 200 || backend.calls != 2 {
		t.Fatalf("status %d after %d provider calls\n%s", status, backend.calls, raw)
	}
	if len(plane.log.authorize) != 2 || plane.log.refund != 1 || len(plane.log.settle) != 1 {
		t.Fatalf("authorize=%d refund=%d settle=%d, want 2/1/1", len(plane.log.authorize), plane.log.refund, len(plane.log.settle))
	}
	// A control-plane verdict is NOT retried: asking again changes nothing.
	denied := &faultyControlPlane{authorizeStatus: func(int) int { return 402 }}
	status, _ = rawDecide(context.Background(), &errorsMidStreamThenAnswers{}, denied.serve(t), nativeBody)
	if status != 402 || len(denied.log.authorize) != 1 {
		t.Fatalf("status %d after %d authorizations, want 402 after exactly one", status, len(denied.log.authorize))
	}
}

func TestNativeDecideNeverRegeneratesAfterSettlementWasAttempted(t *testing.T) {
	// Settlement fails at the TRANSPORT level: the connection drops, so there is
	// no control-plane verdict to read, and the generation may well have been
	// recorded. That must not look like "a provider failure, try again": a
	// second generation would be paid for on top of the first.
	// Atomic: the settle handler hijacks its connection and never responds, so
	// nothing orders its writes before the reads below.
	var authorizations, settles atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/authorize"):
			call := authorizations.Add(1)
			_, _ = fmt.Fprintf(w, `{"data":{"authorization_id":"auth_%d","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-oss-20b","endpoint_id":"e@p/prepaid","provider":"deepinfra","upstream_model":"gpt-oss-20b","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`, call)
		case strings.HasSuffix(request.URL.Path, "/settle"):
			settles.Add(1)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("test server cannot hijack")
			}
			conn, _, _ := hijacker.Hijack()
			_ = conn.Close() // no response at all
		default:
			_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
		}
	}))
	t.Cleanup(server.Close)
	backend := &usageScriptedLLM{replies: []string{goodNative, goodNative}, inputTokens: 400}
	status, raw := rawDecide(context.Background(), backend, trustedrouter.New(server.URL, "internal-token", server.Client()), nativeBody)
	if backend.calls != 1 || authorizations.Load() != 1 {
		t.Fatalf("provider calls=%d authorizations=%d, want exactly one of each: the answer was generated once", backend.calls, authorizations.Load())
	}
	if status < 500 || !saysDoNotRetry(raw) {
		t.Fatalf("status %d, do-not-retry=%v\n%s", status, saysDoNotRetry(raw), raw)
	}
	if settles.Load() == 0 {
		t.Fatal("fixture: settlement was never attempted")
	}
}

// refusesAndCancelsOnTheLast refuses on every host, and the request's context
// goes away as the LAST one answers.
type refusesAndCancelsOnTheLast struct {
	cancel context.CancelFunc
	hosts  int
	called int
}

func (r *refusesAndCancelsOnTheLast) InvokeStreaming(context.Context, *types.OpenAIChatRequest, *types.AnthropicMessagesRequest, io.Writer, ...llm.InvokeOptions) error {
	panic("the hosted decision path must never call the chat client")
}

func (r *refusesAndCancelsOnTheLast) InvokeDecide(context.Context, *llm.DecideRequest, ...llm.InvokeOptions) (*llm.DecideResponse, error) {
	r.called++
	if r.called == r.hosts {
		r.cancel()
	}
	return nil, &llm.DecideError{Provider: "p", Class: llm.DecideErrHTTP, Status: 422}
}

func TestHostedDecideEveryHostRefusingIsA400EvenIfTheRequestIsThenCancelled(t *testing.T) {
	// Both hosts were asked and both said 422. A cancellation arriving with the
	// last answer changes nothing about that. (Clearing the verdict on ANY
	// cancellation made this a 502.)
	plane := &faultyControlPlane{hosted: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := &refusesAndCancelsOnTheLast{cancel: cancel, hosts: 2}
	status, raw := rawDecide(ctx, backend, plane.serve(t), fmt.Sprintf(hostedBody, ""))
	if backend.called != 2 || status != 400 {
		t.Fatalf("hosts asked=%d status=%d, want 2 and 400\n%s", backend.called, status, raw)
	}
	if plane.log.refund != 1 {
		t.Fatalf("refund=%d, want 1 (and it must leave despite the cancellation)", plane.log.refund)
	}
}

// cancelAfterAuthorize is the control-plane transport for a request whose
// context is cancelled the moment its authorization has been fully received:
// what a draining gateway does to a request that is between two steps.
type cancelAfterAuthorize struct {
	inner  http.RoundTripper
	cancel context.CancelFunc
}

func (c cancelAfterAuthorize) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := c.inner.RoundTrip(request)
	if err != nil || !strings.HasSuffix(request.URL.Path, "/authorize") {
		return response, err
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	response.Body = io.NopCloser(bytes.NewReader(body)) // already in memory: reading it cannot fail
	c.cancel()
	return response, nil
}

func TestNativeDecideRefundsAKeyFailureAfterTheRequestWasCancelled(t *testing.T) {
	// A bring-your-own-key route whose key cannot be resolved is refunded by the
	// shared authorize step -- on the request's own context, until now, so a
	// cancellation between the two steps stranded the hold.
	var refunds atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/refund") {
			refunds.Add(1)
			_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_b","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-oss-20b","endpoint_id":"e@p/byok","provider":"deepinfra","upstream_model":"gpt-oss-20b","usage_type":"BYOK","limit_usage_type":"BYOK","route_candidates":[]}}`)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &http.Client{Transport: cancelAfterAuthorize{inner: server.Client().Transport, cancel: cancel}}
	backend := &usageScriptedLLM{replies: []string{goodNative, goodNative}, inputTokens: 400}
	status, raw := rawDecide(ctx, backend, trustedrouter.New(server.URL, "internal-token", client), nativeBody)
	if backend.calls != 0 {
		t.Fatalf("fixture: the key should not have resolved, yet a provider was called %d times", backend.calls)
	}
	if status < 500 {
		t.Fatalf("status %d\n%s", status, raw)
	}
	if got := refunds.Load(); got == 0 {
		t.Fatal("no refund reached the control plane: the hold is stranded until it is reaped")
	}
}

// stopsThenErrors delivers a complete answer and its terminal event, and only
// then fails: an HTTP body that ends badly after everything has arrived.
type stopsThenErrors struct{ calls int }

func (b *stopsThenErrors) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	b.calls++
	if err := (&usageScriptedLLM{replies: []string{goodNative}, inputTokens: 400}).InvokeStreaming(context.Background(), nil, nil, out); err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}

func TestNativeDecideUsesACompleteGenerationDespiteALateTransportError(t *testing.T) {
	// Deliberate, and written down so it stays that way: the generation reached
	// `message_stop`, so it is complete. The answer is used and billed once.
	plane := &faultyControlPlane{}
	backend := &stopsThenErrors{}
	status, raw := rawDecide(context.Background(), backend, plane.serve(t), nativeBody)
	if status != 200 || backend.calls != 1 {
		t.Fatalf("status %d after %d provider calls\n%s", status, backend.calls, raw)
	}
	if len(plane.log.settle) != 1 || plane.log.refund != 0 {
		t.Fatalf("settle=%d refund=%d, want 1/0", len(plane.log.settle), plane.log.refund)
	}
}

// diesAfterTheStopLine finishes a generation -- text, then the stop event's
// `event:` line -- and then the transport fails before the event's data line.
type diesAfterTheStopLine struct{ calls int }

func (b *diesAfterTheStopLine) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	b.calls++
	text, _ := json.Marshal(goodNative)
	_, _ = fmt.Fprintf(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"m","stop_reason":null,"usage":{"input_tokens":400,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%s}}

event: message_stop
`, text)
	return io.ErrUnexpectedEOF
}

func TestNativeDecideRemembersAGenerationThatFinishedAndWasLost(t *testing.T) {
	// The shared collector reports the transport error and drops the text, so
	// each attempt is refunded and the other runs. But a generation was finished
	// and paid for both times, and the final 502 used to invite a third.
	plane := &faultyControlPlane{}
	backend := &diesAfterTheStopLine{}
	status, raw := rawDecide(context.Background(), backend, plane.serve(t), nativeBody)
	if status != 502 || !saysDoNotRetry(raw) {
		t.Fatalf("status %d, do-not-retry=%v\n%s", status, saysDoNotRetry(raw), raw)
	}
	if backend.calls != nativeDecisionAttempts || plane.log.refund != nativeDecisionAttempts || len(plane.log.settle) != 0 {
		t.Fatalf("calls=%d refund=%d settle=%d: the caller is billed for nothing", backend.calls, plane.log.refund, len(plane.log.settle))
	}
	// A provider that never finished anything still invites the retry.
	unfinished := &faultyControlPlane{}
	status, raw = rawDecide(context.Background(), keepaliveThenFail{}, unfinished.serve(t), nativeBody)
	if status != 502 || saysDoNotRetry(raw) {
		t.Fatalf("status %d, do-not-retry=%v: nothing was ever generated", status, saysDoNotRetry(raw))
	}
}
