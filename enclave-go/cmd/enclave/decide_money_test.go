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
	log             controlPlaneLog
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
			_, _ = fmt.Fprintf(w, `{"data":{"authorization_id":"auth_%d","workspace_id":"ws_1","api_key_hash":"key_1","model":%q,"endpoint_id":"e@p/prepaid","provider":"cerebras","upstream_model":"gpt-oss-120b","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`,
				len(f.log.authorize), body["model"])
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
		if plane.log.refund != 1 {
			t.Fatalf("vendor %d: refund=%d, want 1", vendorStatus, plane.log.refund)
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

func TestNativeDecideCountsAModelThatRanAndSaidNothing(t *testing.T) {
	// No text delta ever arrives, so an observer-based "did it run?" says no;
	// then settlement fails and the 503 went out inviting a retry of a call
	// the provider had already been paid for.
	plane := &faultyControlPlane{settleStatus: func(int) int { return 503 }}
	status, raw := rawDecide(context.Background(), silentLLM{}, plane.serve(t), nativeBody)
	if status < 500 || !saysDoNotRetry(raw) {
		t.Fatalf("status %d, do-not-retry=%v\n%s", status, saysDoNotRetry(raw), raw)
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
	if plane.log.refund != 1 || len(plane.log.settle) != 0 {
		t.Fatalf("refund=%d settle=%d, want 1/0", plane.log.refund, len(plane.log.settle))
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
