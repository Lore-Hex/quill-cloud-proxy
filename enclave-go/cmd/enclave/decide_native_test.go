package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
