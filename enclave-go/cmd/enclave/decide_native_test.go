package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// scriptedLLM answers each chat call with the next scripted text, as the
// Anthropic-shaped stream every provider client writes.
type scriptedLLM struct {
	replies  []string
	errors   []error
	requests []*types.OpenAIChatRequest
	options  [][]llm.InvokeOptions
}

func (s *scriptedLLM) InvokeStreaming(_ context.Context, req *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, options ...llm.InvokeOptions) error {
	index := len(s.requests)
	s.requests = append(s.requests, req)
	s.options = append(s.options, options)
	if index >= len(s.replies) {
		return fmt.Errorf("scriptedLLM: unexpected call %d", index+1)
	}
	if index < len(s.errors) && s.errors[index] != nil {
		return s.errors[index]
	}
	text, _ := json.Marshal(s.replies[index])
	_, err := fmt.Fprintf(out, `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"m","stop_reason":null,"usage":{"input_tokens":400,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%s}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":60}}

event: message_stop
data: {"type":"message_stop"}

`, text)
	return err
}

const privateState = "PRIVATE-STATE charged twice for order A-1"

type controlPlaneLog struct {
	authorize              []map[string]any
	settle                 []map[string]any
	refund                 int
	authorizationResponses []string
	settlementResponses    []string
}

func fakeDecideControlPlane(t *testing.T, log *controlPlaneLog, provider string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read control-plane request: %v", err)
		}
		// The whole point of the attested gateway: the control plane bills on
		// metadata and never sees what is being decided.
		if bytes.Contains(raw, []byte("PRIVATE-STATE")) || bytes.Contains(raw, []byte("Is a refund requested")) {
			t.Fatalf("control plane received decision content on %s: %s", request.URL.Path, raw)
		}
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		switch request.URL.Path {
		case "/internal/gateway/authorize":
			log.authorize = append(log.authorize, body)
			if len(log.authorizationResponses) > 0 {
				_, _ = fmt.Fprint(w, log.authorizationResponses[len(log.authorize)-1])
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":{"authorization_id":"auth_%d","workspace_id":"ws_1","api_key_hash":"key_1","model":%q,"endpoint_id":"e@p/prepaid","provider":%q,"upstream_model":"gpt-oss-120b","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`,
				len(log.authorize), body["model"], provider)
		case "/internal/gateway/settle":
			log.settle = append(log.settle, body)
			if len(log.settlementResponses) > 0 {
				_, _ = fmt.Fprint(w, log.settlementResponses[len(log.settle)-1])
				return
			}
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_1","cost_microdollars":360,"model":"m","provider":"p","region":"us-central1"}}`)
		case "/internal/gateway/refund":
			log.refund++
			_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", request.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func runNativeDecide(t *testing.T, model string, extra string, backend *scriptedLLM, log *controlPlaneLog) (int, map[string]any) {
	t.Helper()
	controlPlane := fakeDecideControlPlane(t, log, "cerebras")
	gateway := trustedrouter.New(controlPlane.URL, "internal-token", controlPlane.Client())
	body := fmt.Sprintf(`{"model":%q,%s"state":%q,"questions":{
	  "refund":{"type":"boolean","instructions":"Is a refund requested?"},
	  "route":{"type":"choice","instructions":"Route it.","criteria":{"billing":"charges","shipping":"delivery"}}}}`, model, extra, privateState)
	var out bytes.Buffer
	serveDecide(context.Background(), &out, backend, []byte(body), gateway, true, "sk-tr-test-bearer", nil, "idem-1", requestAttributionHeaders{}, "log-1")
	raw := out.String()
	status := 0
	_, _ = fmt.Sscanf(strings.Fields(strings.SplitN(raw, "\r\n", 2)[0])[1], "%d", &status)
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	var payload map[string]any
	if len(parts) == 2 {
		_ = json.Unmarshal([]byte(parts[1]), &payload)
	}
	return status, payload
}

const goodNative = `{"q0":0.97,"q1":{"q1_o0":0.9,"q1_o1":0.1}}`

func nativeRouteAuthorization(attempt string, hidden, fallback bool) string {
	provider := "cerebras"
	if attempt == "second" {
		provider = "sambanova"
	}
	route := fmt.Sprintf(`{"model":%q,"provider":%q,"endpoint_id":%q,"upstream_model":"gpt-oss-120b","usage_type":"Credits"}`, attempt, provider, attempt+"@"+provider+"/prepaid")
	candidates := route
	model, endpoint := attempt, attempt+"@"+provider+"/prepaid"
	if fallback {
		candidates = `{"model":"failed-model","provider":"fireworks","endpoint_id":"failed@fireworks/prepaid","upstream_model":"gpt-oss-120b","usage_type":"Credits"},` + route
		model, provider, endpoint = "failed-model", "fireworks", "failed@fireworks/prepaid"
	}
	return fmt.Sprintf(`{"data":{"authorization_id":%q,"workspace_id":"ws_1","api_key_hash":"key_1","model":%q,"provider":%q,"endpoint_id":%q,"upstream_model":"gpt-oss-120b","usage_type":"Credits","limit_usage_type":"Credits","response_model":%q,"hide_public_metadata":%t,"route_candidates":[%s]}}`,
		"auth_"+attempt, model, provider, endpoint, "public-"+attempt, hidden, candidates)
}

func nativeRouteSettlement(attempt, provider string) string {
	return fmt.Sprintf(`{"data":{"settled":true,"generation_id":%q,"cost_microdollars":360,"model":%q,"provider":%q,"region":"us-central1"}}`, "gen_"+attempt, "settled-"+attempt, provider)
}

func TestNativeDecideBillsAsOneChatCallAndReturnsTheContractShape(t *testing.T) {
	backend := &scriptedLLM{replies: []string{goodNative}}
	log := &controlPlaneLog{}
	status, payload := runNativeDecide(t, decide.TrevModelID, "", backend, log)
	if status != 200 {
		t.Fatalf("status %d: %v", status, payload)
	}
	assertDecideRouting(t, payload, `{"selected_model":"m","selected_provider":"p","selected_endpoint":"e@p/prepaid","fallback_candidate_count":1,"upstream_attempt_count":1,"fallback_attempt_count":0}`)
	// The caller sees the NAME they asked for, never the backing model.
	if payload["model"] != decide.TrevModelID {
		t.Fatalf("response model = %v", payload["model"])
	}
	encoded, _ := json.Marshal(payload["answers"])
	if string(encoded) != `{"refund":{"probability":0.97,"type":"boolean"},"route":{"choice":"billing","probabilities":{"billing":0.9,"shipping":0.1},"type":"choice"}}` {
		t.Fatalf("answers drifted from the decision contract: %s", encoded)
	}
	if len(log.authorize) != 1 || len(log.settle) != 1 || log.refund != 0 {
		t.Fatalf("authorize=%d settle=%d refund=%d", len(log.authorize), len(log.settle), log.refund)
	}
	authorize := log.authorize[0]
	if authorize["route_type"] != "decide" || authorize["model"] != decide.TrevModelID {
		t.Fatalf("authorize body: %v", authorize)
	}
	provider, _ := authorize["provider"].(map[string]any)
	if fmt.Sprint(provider["only"]) != "[cerebras sambanova fireworks together]" || fmt.Sprint(provider["order"]) != "[cerebras sambanova fireworks together]" {
		t.Fatalf("trev must be authorized on its pinned hosts only: %v", provider)
	}
	if got := log.settle[0]["route_type"]; got != "decide" {
		t.Fatalf("settle route_type = %v", got)
	}
	// What the model was actually sent: the prompt with the state and the
	// output skeleton, prompt format (no response_format), effort string only.
	sent := backend.requests[0]
	prompt, _ := sent.Messages[1].Content.(string)
	if !strings.Contains(prompt, privateState) || !strings.Contains(prompt, `{"q0":P,"q1":{"q1_o0":P,"q1_o1":P}}`) {
		t.Fatalf("prompt missing state or skeleton:\n%s", prompt)
	}
	if sent.ResponseFormat != nil || sent.ReasoningEffort != "low" || sent.Reasoning != nil || sent.Stream {
		t.Fatalf("trev request shape: format=%v effort=%q reasoning=%v stream=%v", sent.ResponseFormat, sent.ReasoningEffort, sent.Reasoning, sent.Stream)
	}
	usage, _ := payload["usage"].(map[string]any)
	if usage["inputTokens"] != float64(400) || usage["outputTokens"] != float64(60) {
		t.Fatalf("usage = %v", usage)
	}
}

func TestNativeDecideRetriesOnceWhenTheSecondPassRejectsTheAnswer(t *testing.T) {
	// First reply is fluent and wrong in form: a word where a number belongs.
	backend := &scriptedLLM{replies: []string{`{"q0":"likely","q1":{"q1_o0":1,"q1_o1":0}}`, "```json\n" + goodNative + "\n```"}}
	log := &controlPlaneLog{
		authorizationResponses: []string{nativeRouteAuthorization("first", false, false), nativeRouteAuthorization("second", false, false)},
		settlementResponses:    []string{nativeRouteSettlement("first", "billed-first"), nativeRouteSettlement("second", "billed-second")},
	}
	status, payload := runNativeDecide(t, "openai/gpt-oss-20b", "", backend, log)
	if status != 200 {
		t.Fatalf("status %d: %v", status, payload)
	}
	assertDecideRouting(t, payload, `{"selected_model":"settled-second","selected_provider":"billed-second","selected_endpoint":"second@sambanova/prepaid","fallback_candidate_count":1,"upstream_attempt_count":2,"fallback_attempt_count":0}`)
	if len(backend.requests) != 2 || len(log.authorize) != 2 || len(log.settle) != 2 {
		t.Fatalf("calls=%d authorize=%d settle=%d; both attempts spend tokens and both are billed", len(backend.requests), len(log.authorize), len(log.settle))
	}
	// Each attempt is its own generation, so it needs its own idempotency key.
	if log.authorize[0]["idempotency_key"] == log.authorize[1]["idempotency_key"] {
		t.Fatalf("retry reused idempotency key %v", log.authorize[0]["idempotency_key"])
	}
	usage, _ := payload["usage"].(map[string]any)
	if usage["inputTokens"] != float64(800) || usage["outputTokens"] != float64(120) {
		t.Fatalf("usage must report both attempts: %v", usage)
	}
}

func TestNativeDecideCountsUpstreamAttemptsAndKeepsTheServedProvider(t *testing.T) {
	down := fmt.Errorf("llm/upstream: http 503: unavailable")
	for _, tc := range []struct {
		name     string
		replies  []string
		errors   []error
		refunds  int
		settles  int
		attempts int
	}{
		{"internal failover", []string{"", goodNative}, []error{down, nil}, 0, 1, 2},
		{"invalid answer then failover again", []string{"", "invalid", "", goodNative}, []error{down, nil, down, nil}, 0, 2, 4},
		{"refunded call then failover again", []string{"", "", "", goodNative}, []error{down, down, down, nil}, 1, 1, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &scriptedLLM{replies: tc.replies, errors: tc.errors}
			log := &controlPlaneLog{
				authorizationResponses: []string{nativeRouteAuthorization("first", false, true), nativeRouteAuthorization("second", false, true)},
				// Missing settlement provider must retain the answering candidate's
				// provider, including when it differs from the authorization's first route.
				settlementResponses: []string{`{"data":{"settled":true}}`, `{"data":{"settled":true}}`},
			}
			status, payload := runNativeDecide(t, "openai/gpt-oss-20b", "", backend, log)
			if status != 200 {
				t.Fatalf("status %d: %v", status, payload)
			}
			model, provider := "first", "cerebras"
			if tc.attempts == 4 {
				model, provider = "second", "sambanova"
			}
			assertDecideRouting(t, payload, fmt.Sprintf(`{"selected_model":%q,"selected_provider":%q,"selected_endpoint":%q,"fallback_candidate_count":2,"upstream_attempt_count":%d,"fallback_attempt_count":%d}`, model, provider, model+"@"+provider+"/prepaid", tc.attempts, tc.attempts/2))
			if len(backend.requests) != tc.attempts || log.refund != tc.refunds || len(log.settle) != tc.settles {
				t.Fatalf("calls=%d refunds=%d settlements=%d", len(backend.requests), log.refund, len(log.settle))
			}
		})
	}
}

func TestNativeDecideCountsOnlyCandidatesWithAvailableKeys(t *testing.T) {
	t.Setenv("DECIDE_TEST_UNAVAILABLE_BYOK_KEY", "")
	backend := &scriptedLLM{replies: []string{goodNative}}
	log := &controlPlaneLog{
		authorizationResponses: []string{`{"data":{"authorization_id":"auth_filtered","workspace_id":"ws_1","api_key_hash":"key_1",
			"model":"openai/gpt-oss-20b","provider":"cerebras","endpoint_id":"first@cerebras/byok","usage_type":"BYOK","limit_usage_type":"Credits",
			"route_candidates":[
				{"model":"openai/gpt-oss-20b","provider":"cerebras","endpoint_id":"first@cerebras/byok","usage_type":"BYOK","byok_secret_ref":"env://DECIDE_TEST_UNAVAILABLE_BYOK_KEY"},
				{"model":"openai/gpt-oss-20b","provider":"sambanova","endpoint_id":"second@sambanova/prepaid","usage_type":"Credits"}]}}`},
		settlementResponses: []string{`{"data":{"settled":true}}`},
	}
	// The first candidate's secret is unavailable, so only the credits route runs.
	status, payload := runNativeDecide(t, "openai/gpt-oss-20b", "", backend, log)
	if status != 200 {
		t.Fatalf("status %d: %v", status, payload)
	}
	assertDecideRouting(t, payload, `{"selected_model":"openai/gpt-oss-20b","selected_provider":"sambanova","selected_endpoint":"second@sambanova/prepaid","fallback_candidate_count":1,"upstream_attempt_count":1,"fallback_attempt_count":0}`)
	if len(backend.options) != 1 || len(backend.options[0]) != 1 || backend.options[0][0].EndpointID != "second@sambanova/prepaid" {
		t.Fatalf("invoke options = %v; only the credits candidate should be called", backend.options)
	}
	if len(log.authorize) != 1 || len(log.settle) != 1 || log.refund != 0 {
		t.Fatalf("authorize=%d settle=%d refund=%d", len(log.authorize), len(log.settle), log.refund)
	}
}

func TestNativeDecidePrivacyUsesTheAnsweringAttemptsAuthorization(t *testing.T) {
	for _, hideSecond := range []bool{false, true} {
		t.Run(fmt.Sprintf("hide_second_%t", hideSecond), func(t *testing.T) {
			backend := &scriptedLLM{replies: []string{"invalid", goodNative}}
			log := &controlPlaneLog{
				authorizationResponses: []string{nativeRouteAuthorization("first", !hideSecond, false), nativeRouteAuthorization("second", hideSecond, false)},
				settlementResponses:    []string{nativeRouteSettlement("first", "billed-first"), nativeRouteSettlement("second", "billed-second")},
			}
			status, payload := runNativeDecide(t, "openai/gpt-oss-20b", "", backend, log)
			if status != 200 {
				t.Fatalf("status %d: %v", status, payload)
			}
			want := `{"selected_model":"settled-second","selected_provider":"billed-second","selected_endpoint":"second@sambanova/prepaid","fallback_candidate_count":1,"upstream_attempt_count":2,"fallback_attempt_count":0}`
			if hideSecond {
				want = `{"selected_model":"public-second","selected_provider":"trustedrouter","fallback_candidate_count":1,"upstream_attempt_count":2,"fallback_attempt_count":0}`
			}
			assertDecideRouting(t, payload, want)
		})
	}
}

func TestNativeDecideNeverReturnsAnAnswerItCouldNotVerify(t *testing.T) {
	backend := &scriptedLLM{replies: []string{"I think they want a refund.", `{"q0":0.9,"q1":{"q1_o0":0.9,"q1_o1":0.9}}`}}
	log := &controlPlaneLog{}
	status, payload := runNativeDecide(t, "google/gemma-4-e4b-it", "", backend, log)
	if status != 502 {
		t.Fatalf("status %d, want 502: %v", status, payload)
	}
	if _, leaked := payload["answers"]; leaked {
		t.Fatalf("an unverified answer reached the caller: %v", payload)
	}
	if len(backend.requests) != 2 {
		t.Fatalf("attempts = %d, want exactly 2", len(backend.requests))
	}
}

func TestNativeDecideOptionsReachTheModelAndAnyChatModelWorks(t *testing.T) {
	backend := &scriptedLLM{replies: []string{goodNative}}
	log := &controlPlaneLog{}
	status, payload := runNativeDecide(t, "anthropic/claude-opus-5",
		`"reasoning":{"effort":"high"},"provider":{"only":["anthropic"]},`, backend, log)
	if status != 200 {
		t.Fatalf("status %d: %v", status, payload)
	}
	sent := backend.requests[0]
	// As the effort STRING, which every host understands. The object the
	// caller wrote is not portable (Cerebras answers 400 to it), so it is
	// reduced to the one validated word and never forwarded.
	if sent.ReasoningEffort != "high" || sent.Reasoning != nil {
		t.Fatalf("caller reasoning must reach the model as the effort word: effort=%q object=%v", sent.ReasoningEffort, sent.Reasoning)
	}
	if sent.Provider == nil || strings.Join(sent.Provider.Only, ",") != "anthropic" {
		t.Fatalf("caller provider not forwarded: %+v", sent.Provider)
	}
	if sent.ResponseFormat != nil || sent.Temperature != nil {
		t.Fatalf("an untuned model must not be sent host-specific controls: %+v", sent)
	}
	if *sent.MaxTokens < 8192 {
		t.Fatalf("reasoning needs token headroom, got max_tokens=%d", *sent.MaxTokens)
	}
}

// captureStderr runs fn and returns everything it wrote to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writer
	done := make(chan string)
	go func() {
		raw, _ := io.ReadAll(reader)
		done <- string(raw)
	}()
	fn()
	os.Stderr = original
	_ = writer.Close()
	return <-done
}

func TestDecideLogsNeverCarryRequestContent(t *testing.T) {
	// Both attempts fail verification in ways whose REASON quotes the caller's
	// own option names and the model's words. None of it may reach a log.
	backend := &scriptedLLM{replies: []string{
		`{"q0":"SECRET-MODEL-WORDS","q1":{"q1_o0":1,"q1_o1":0}}`,
		`{"q0":0.9,"q1":{"q1_o0":0.5,"SECRET-INVENTED-OPTION":0.5}}`,
	}}
	log := &controlPlaneLog{}
	var status int
	stderr := captureStderr(t, func() {
		status, _ = runNativeDecide(t, "openai/gpt-oss-20b", "", backend, log)
	})
	if status != 502 {
		t.Fatalf("status %d, want 502", status)
	}
	for _, leaked := range []string{"PRIVATE-STATE", "SECRET-MODEL-WORDS", "SECRET-INVENTED-OPTION", "Is a refund requested", "billing", "charges"} {
		if strings.Contains(stderr, leaked) {
			t.Errorf("stderr carries request or model content %q:\n%s", leaked, stderr)
		}
	}
	// ...while still saying enough to diagnose it.
	for _, want := range []string{`enclave.decide_verification_failed`, `kind="not_a_number"`, `kind="option_set"`, `attempt=2`} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is missing %q:\n%s", want, stderr)
		}
	}
}

// hostScriptedDecider answers a hosted decision per PROVIDER, so a test can take
// the preferred host down and watch the gateway move to the next one.
type hostScriptedDecider struct {
	failing map[string]error
	answers map[string]decide.Answer
	called  []string
}

func (h *hostScriptedDecider) InvokeStreaming(context.Context, *types.OpenAIChatRequest, *types.AnthropicMessagesRequest, io.Writer, ...llm.InvokeOptions) error {
	panic("the hosted decision path must never call the chat client")
}

func (h *hostScriptedDecider) InvokeDecide(_ context.Context, _ *llm.DecideRequest, options ...llm.InvokeOptions) (*llm.DecideResponse, error) {
	provider := ""
	if len(options) > 0 {
		provider = options[0].Provider
	}
	h.called = append(h.called, provider)
	if err := h.failing[provider]; err != nil {
		return nil, err
	}
	return &llm.DecideResponse{Answers: h.answers, InputTokens: 444, OutputTokens: 30}, nil
}

func hostedControlPlane(t *testing.T, log *controlPlaneLog) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		raw, _ := io.ReadAll(request.Body)
		if bytes.Contains(raw, []byte("PRIVATE-STATE")) {
			t.Fatalf("control plane received decision content on %s", request.URL.Path)
		}
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		switch request.URL.Path {
		case "/internal/gateway/authorize":
			log.authorize = append(log.authorize, body)
			_, _ = fmt.Fprint(w, `{"data":{"authorization_id":"auth_h","workspace_id":"ws_1","api_key_hash":"key_1",
			 "model":"typesafe-ai/jev","endpoint_id":"typesafe-ai/jev@typesafe/prepaid","provider":"typesafe","upstream_model":"jev-latest",
			 "usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[
			  {"endpoint_id":"typesafe-ai/jev@typesafe/prepaid","model":"typesafe-ai/jev","upstream_model":"jev-latest","provider":"typesafe","usage_type":"Credits"},
			  {"endpoint_id":"typesafe-ai/jev-relay@vercel-ai-gateway/prepaid","model":"typesafe-ai/jev-relay","upstream_model":"typesafe-ai/jev","provider":"vercel-ai-gateway","usage_type":"Credits"}]}}`)
		case "/internal/gateway/settle":
			log.settle = append(log.settle, body)
			model, host, _ := strings.Cut(body["selected_endpoint"].(string), "@")
			provider, _, _ := strings.Cut(host, "/")
			_, _ = fmt.Fprintf(w, `{"data":{"settled":true,"generation_id":"gen_h","cost_microdollars":20,"model":%q,"provider":%q,"region":"us-central1"}}`, model, provider)
		case "/internal/gateway/refund":
			log.refund++
			_, _ = fmt.Fprint(w, `{"data":{"refunded":true}}`)
		default:
			t.Fatalf("unexpected control-plane path %s", request.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func runHostedDecide(t *testing.T, backend llm.Client, log *controlPlaneLog) (int, map[string]any) {
	t.Helper()
	controlPlane := hostedControlPlane(t, log)
	gateway := trustedrouter.New(controlPlane.URL, "internal-token", controlPlane.Client())
	body := fmt.Sprintf(`{"model":"typesafe-ai/jev","state":%q,"questions":{
	  "refund":{"type":"boolean","instructions":"Is a refund requested?"},
	  "route":{"type":"choice","instructions":"Route it.","criteria":{"billing":"charges","shipping":"delivery"}}}}`, privateState)
	var out bytes.Buffer
	serveDecide(context.Background(), &out, backend, []byte(body), gateway, true, "sk-tr-test-bearer", nil, "idem-h", requestAttributionHeaders{}, "log-h")
	raw := out.String()
	status := 0
	_, _ = fmt.Sscanf(strings.Fields(strings.SplitN(raw, "\r\n", 2)[0])[1], "%d", &status)
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	var payload map[string]any
	if len(parts) == 2 {
		_ = json.Unmarshal([]byte(parts[1]), &payload)
	}
	return status, payload
}

func hostedAnswers() map[string]decide.Answer {
	p, choice := 0.97, "billing"
	return map[string]decide.Answer{
		"refund": {Type: decide.TypeBoolean, Probability: &p},
		"route":  {Type: decide.TypeChoice, Choice: &choice, Probabilities: map[string]float64{"billing": 0.9, "shipping": 0.1}},
	}
}

func TestHostedDecidePrefersTheVendorAndBillsInputOnly(t *testing.T) {
	backend := &hostScriptedDecider{answers: hostedAnswers()}
	log := &controlPlaneLog{}
	status, payload := runHostedDecide(t, backend, log)
	if status != 200 {
		t.Fatalf("status %d: %v", status, payload)
	}
	assertDecideRouting(t, payload, `{"selected_model":"typesafe-ai/jev","selected_provider":"typesafe","selected_endpoint":"typesafe-ai/jev@typesafe/prepaid","fallback_candidate_count":2,"upstream_attempt_count":1,"fallback_attempt_count":0}`)
	if strings.Join(backend.called, ",") != "typesafe" {
		t.Fatalf("hosts called = %v; the relay must not be touched when the vendor answers", backend.called)
	}
	settle := log.settle[0]
	if settle["actual_output_tokens"] != float64(0) || settle["actual_input_tokens"] != float64(444) {
		t.Fatalf("hosted decisions bill input only: %v", settle)
	}
	if settle["selected_endpoint"] != "typesafe-ai/jev@typesafe/prepaid" {
		t.Fatalf("settled against %v", settle["selected_endpoint"])
	}
}

func TestHostedDecideFailsOverToTheRelayAndSettlesAgainstIt(t *testing.T) {
	backend := &hostScriptedDecider{
		answers: hostedAnswers(),
		failing: map[string]error{"typesafe": fmt.Errorf("llm/upstream: http 529: overloaded")},
	}
	log := &controlPlaneLog{}
	status, payload := runHostedDecide(t, backend, log)
	if status != 200 {
		t.Fatalf("status %d: %v", status, payload)
	}
	assertDecideRouting(t, payload, `{"selected_model":"typesafe-ai/jev-relay","selected_provider":"vercel-ai-gateway","selected_endpoint":"typesafe-ai/jev-relay@vercel-ai-gateway/prepaid","fallback_candidate_count":2,"upstream_attempt_count":2,"fallback_attempt_count":1}`)
	if strings.Join(backend.called, ",") != "typesafe,vercel-ai-gateway" {
		t.Fatalf("hosts called = %v", backend.called)
	}
	if len(log.settle) != 1 || log.refund != 0 {
		t.Fatalf("settle=%d refund=%d; one answer was delivered, so exactly one settlement", len(log.settle), log.refund)
	}
	if got := log.settle[0]["selected_endpoint"]; got != "typesafe-ai/jev-relay@vercel-ai-gateway/prepaid" {
		t.Fatalf("settled against %v, not the host that served", got)
	}
}

func TestHostedDecideRefundsWhenEveryHostIsDown(t *testing.T) {
	down := fmt.Errorf("llm/upstream: http 529: overloaded")
	backend := &hostScriptedDecider{failing: map[string]error{"typesafe": down, "vercel-ai-gateway": down}}
	log := &controlPlaneLog{}
	status, payload := runHostedDecide(t, backend, log)
	if status != 502 {
		t.Fatalf("status %d, want 502: %v", status, payload)
	}
	if len(backend.called) != 2 || len(log.settle) != 0 || log.refund != 1 {
		t.Fatalf("called=%v settle=%d refund=%d; nothing was delivered, so refund once and never settle", backend.called, len(log.settle), log.refund)
	}
}

func TestEveryNamedDecisionModelIsDrivenOnItsOwnHostAndAnswersUnderItsName(t *testing.T) {
	// The control plane RESOLVES a name: authorize answers with the concrete chat
	// model, its host and its upstream id. The fake used elsewhere echoes the
	// requested model back, so against it "the response keeps the name" could
	// not fail -- returning the authorized model would have passed too.
	type resolved struct{ hosts, model, provider, upstream string }
	for name, want := range map[string]resolved{
		decide.TrevModelID: {"cerebras,sambanova,fireworks,together", "openai/gpt-oss-120b", "cerebras", "gpt-oss-120b"},
		decide.GevModelID:  {"google-ai-studio", "google/gemini-3.1-flash-lite", "google-ai-studio", "gemini-3.1-flash-lite"},
		// Authorize may select any host in the chain; exercise DeepInfra here.
		decide.DevModelID:    {"wafer,deepinfra,wandb", "deepseek/deepseek-v4.1-flash", "deepinfra", "deepseek-ai/DeepSeek-V4.1-Flash"},
		decide.OevModelID:    {"deepinfra", "openai/gpt-oss-20b", "deepinfra", "openai/gpt-oss-20b"},
		decide.GemmevModelID: {"deepinfra", "google/gemma-4-e4b-it", "deepinfra", "google/gemma-4-E4B-it"},
		decide.MevModelID:    {"inception", "inception/mercury-2", "inception", "mercury-2"},
		decide.ZevModelID:    {"fireworks,baseten", "z-ai/glm-5.2-fast", "fireworks", "accounts/fireworks/routers/glm-5p2-fast"},
		decide.LevModelID:    {"sambanova,parasail,together", "meta-llama/llama-3.3-70b-instruct", "sambanova", "Meta-Llama-3.3-70B-Instruct"},
	} {
		var authorized, settled []map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			raw, _ := io.ReadAll(request.Body)
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			switch request.URL.Path {
			case "/internal/gateway/authorize":
				authorized = append(authorized, body)
				_, _ = fmt.Fprintf(w, `{"data":{"authorization_id":"auth_1","workspace_id":"ws_1","api_key_hash":"key_1","model":%q,"response_model":%q,"hide_public_metadata":true,"endpoint_id":%q,"provider":%q,"upstream_model":%q,"usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`,
					want.model, name, want.model+"@"+want.provider+"/prepaid", want.provider, want.upstream)
			case "/internal/gateway/settle":
				settled = append(settled, body)
				// Settlement answers with the concrete model and host, as the
				// control plane does. Placeholders here would let a response
				// that copied them out pass the "reveals nothing" check below.
				_, _ = fmt.Fprintf(w, `{"data":{"settled":true,"generation_id":"gen_1","cost_microdollars":360,"model":%q,"provider":%q,"region":"us-central1"}}`, want.model, want.provider)
			default:
				t.Fatalf("%s: unexpected control-plane path %s", name, request.URL.Path)
			}
		}))
		gateway := trustedrouter.New(server.URL, "internal-token", server.Client())
		backend := &scriptedLLM{replies: []string{goodNative}}
		body := fmt.Sprintf(`{"model":%q,"state":%q,"questions":{
		  "refund":{"type":"boolean","instructions":"Is a refund requested?"},
		  "route":{"type":"choice","instructions":"Route it.","criteria":{"billing":"charges","shipping":"delivery"}}}}`, name, privateState)
		var out bytes.Buffer
		serveDecide(context.Background(), &out, backend, []byte(body), gateway, true, "sk-tr-test-bearer", nil, "idem-n", requestAttributionHeaders{}, "log-n")
		server.Close()
		raw := out.String()
		if !strings.HasPrefix(raw, "HTTP/1.1 200") {
			t.Fatalf("%s: %s", name, raw)
		}
		var payload map[string]any
		_ = json.Unmarshal([]byte(strings.SplitN(raw, "\r\n\r\n", 2)[1]), &payload)
		assertDecideRouting(t, payload, fmt.Sprintf(`{"selected_model":%q,"selected_provider":"trustedrouter","fallback_candidate_count":1,"upstream_attempt_count":1,"fallback_attempt_count":0}`, name))
		if strings.Contains(raw, "us-central1") || strings.Contains(raw, `"region"`) {
			t.Errorf("%s: the response reveals the region: %s", name, raw)
		}

		// What the caller sees: the name, and nothing of what is behind it.
		if payload["model"] != name {
			t.Errorf("%s: response model = %v", name, payload["model"])
		}
		for _, hidden := range []string{want.model, want.upstream, want.provider} {
			if strings.Contains(raw, hidden) {
				t.Errorf("%s: the response reveals %q:\n%s", name, hidden, raw)
			}
		}
		// What the control plane is asked: the NAME (resolving it is its job), on
		// exactly the name's hosts, in order.
		if len(authorized) != 1 || authorized[0]["model"] != name || authorized[0]["route_type"] != decideRouteType {
			t.Fatalf("%s: authorized as %v", name, authorized)
		}
		// Read off the authorize BODY: the control plane filters candidates by
		// what arrives there, and this fake routes to the right host whatever it
		// is sent, so the chat request alone would not show a wrong list.
		preferences, _ := authorized[0]["provider"].(map[string]any)
		if got, wantFallbacks := preferences["allow_fallbacks"], strings.Contains(want.hosts, ","); got != wantFallbacks {
			t.Errorf("%s: authorize provider.allow_fallbacks = %v, want %t", name, got, wantFallbacks)
		}
		for _, field := range []string{"only", "order"} {
			if got := joinedStrings(preferences[field]); got != want.hosts {
				t.Errorf("%s: authorize provider.%s = %q, want exactly %q in order", name, field, got, want.hosts)
			}
		}
		sent := backend.requests[0]
		// What the PROVIDER is asked: the concrete model the control plane
		// resolved, on its host, under its upstream id. Provider-specific request
		// shaping keys on these, so they must not be the name.
		if sent.Model != want.model {
			t.Errorf("%s: provider request model = %q, want the resolved %q", name, sent.Model, want.model)
		}
		if len(backend.options) != 1 || len(backend.options[0]) == 0 {
			t.Fatalf("%s: no invoke options recorded", name)
		}
		if option := backend.options[0][0]; option.Provider != want.provider || option.UpstreamModel != want.upstream {
			t.Errorf("%s: invoked %s/%s, want %s/%s", name, option.Provider, option.UpstreamModel, want.provider, want.upstream)
		}
		// What is SETTLED: this authorization, against the concrete model and
		// endpoint that served it (the name has no price of its own), for the
		// tokens the provider reported.
		if len(settled) != 1 {
			t.Fatalf("%s: settle=%d", name, len(settled))
		}
		for field, expected := range map[string]any{
			"authorization_id":     "auth_1",
			"selected_model":       want.model,
			"selected_endpoint":    want.model + "@" + want.provider + "/prepaid",
			"actual_input_tokens":  float64(400),
			"actual_output_tokens": float64(60),
			"route_type":           decideRouteType,
			"status":               "success",
		} {
			if settled[0][field] != expected {
				t.Errorf("%s: settle %s = %v, want %v", name, field, settled[0][field], expected)
			}
		}
	}
}

// joinedStrings renders a decoded JSON array of strings as "a,b,c".
func joinedStrings(value any) string {
	items, _ := value.([]any)
	parts := make([]string, 0, len(items))
	for _, item := range items {
		text, _ := item.(string)
		parts = append(parts, text)
	}
	return strings.Join(parts, ",")
}
