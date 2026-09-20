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
	authorize []map[string]any
	settle    []map[string]any
	refund    int
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
			_, _ = fmt.Fprintf(w, `{"data":{"authorization_id":"auth_%d","workspace_id":"ws_1","api_key_hash":"key_1","model":%q,"endpoint_id":"e@p/prepaid","provider":%q,"upstream_model":"gpt-oss-120b","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`,
				len(log.authorize), body["model"], provider)
		case "/internal/gateway/settle":
			log.settle = append(log.settle, body)
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

func TestNativeDecideBillsAsOneChatCallAndReturnsTheContractShape(t *testing.T) {
	backend := &scriptedLLM{replies: []string{goodNative}}
	log := &controlPlaneLog{}
	status, payload := runNativeDecide(t, decide.TrevModelID, "", backend, log)
	if status != 200 {
		t.Fatalf("status %d: %v", status, payload)
	}
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
	log := &controlPlaneLog{}
	status, payload := runNativeDecide(t, "openai/gpt-oss-20b", "", backend, log)
	if status != 200 {
		t.Fatalf("status %d: %v", status, payload)
	}
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
	reasoning, _ := sent.Reasoning.(map[string]any)
	if reasoning["effort"] != "high" {
		t.Fatalf("caller reasoning not forwarded: %v", sent.Reasoning)
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
			  {"endpoint_id":"typesafe-ai/jev@vercel-ai-gateway/prepaid","model":"typesafe-ai/jev","upstream_model":"typesafe-ai/jev","provider":"vercel-ai-gateway","usage_type":"Credits"}]}}`)
		case "/internal/gateway/settle":
			log.settle = append(log.settle, body)
			_, _ = fmt.Fprint(w, `{"data":{"settled":true,"generation_id":"gen_h","cost_microdollars":20,"model":"typesafe-ai/jev","provider":"p","region":"us-central1"}}`)
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
	if strings.Join(backend.called, ",") != "typesafe,vercel-ai-gateway" {
		t.Fatalf("hosts called = %v", backend.called)
	}
	if len(log.settle) != 1 || log.refund != 0 {
		t.Fatalf("settle=%d refund=%d; one answer was delivered, so exactly one settlement", len(log.settle), log.refund)
	}
	if got := log.settle[0]["selected_endpoint"]; got != "typesafe-ai/jev@vercel-ai-gateway/prepaid" {
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
