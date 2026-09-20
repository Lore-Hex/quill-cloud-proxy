package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// fakeDecider is a gateway client whose hosted decision model returns whatever
// the test says — including answers that break the contract.
type fakeDecider struct {
	answers map[string]decide.Answer
	calls   int
	seen    *llm.DecideRequest
}

func (f *fakeDecider) InvokeStreaming(context.Context, *types.OpenAIChatRequest, *types.AnthropicMessagesRequest, io.Writer, ...llm.InvokeOptions) error {
	panic("the hosted decision path must never call the chat client")
}

func (f *fakeDecider) InvokeDecide(_ context.Context, req *llm.DecideRequest, _ ...llm.InvokeOptions) (*llm.DecideResponse, error) {
	f.calls++
	f.seen = req
	return &llm.DecideResponse{Answers: f.answers, InputTokens: 300, OutputTokens: 20}, nil
}

type chatOnlyClient struct{}

func (chatOnlyClient) InvokeStreaming(context.Context, *types.OpenAIChatRequest, *types.AnthropicMessagesRequest, io.Writer, ...llm.InvokeOptions) error {
	return nil
}

const decideBody = `{"model":"typesafe-ai/jev","state":"charged twice",
 "questions":{"refund":{"type":"boolean","instructions":"refund?"},
              "route":{"type":"choice","instructions":"route","criteria":{"billing":"b","shipping":"s"}}}}`

func runDecide(t *testing.T, br llm.Client, body string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	serveDecide(context.Background(), &out, br, []byte(body), nil, false, "", nil, "", requestAttributionHeaders{}, "log-1")
	raw := out.String()
	fields := strings.Fields(strings.SplitN(raw, "\r\n", 2)[0])
	if len(fields) < 2 {
		t.Fatalf("no status line in %q", raw)
	}
	status := 0
	if err := json.Unmarshal([]byte(fields[1]), &status); err != nil {
		t.Fatalf("status %q: %v", fields[1], err)
	}
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	if len(parts) != 2 {
		return status, ""
	}
	return status, parts[1]
}

func pf(v float64) *float64 { return &v }
func ps(v string) *string   { return &v }

func TestDecideRejectsMalformedRequestsBeforeAnyUpstreamCall(t *testing.T) {
	cases := map[string]string{
		"not json":        `{`,
		"no model":        `{"state":"x","questions":{"a":{"type":"boolean","instructions":"x"}}}`,
		"stream":          `{"model":"typesafe-ai/jev","stream":true,"state":"x","questions":{"a":{"type":"boolean","instructions":"x"}}}`,
		"no state":        `{"model":"typesafe-ai/jev","questions":{"a":{"type":"boolean","instructions":"x"}}}`,
		"numeric state":   `{"model":"typesafe-ai/jev","state":7,"questions":{"a":{"type":"boolean","instructions":"x"}}}`,
		"no questions":    `{"model":"typesafe-ai/jev","state":"x","questions":{}}`,
		"bad type":        `{"model":"typesafe-ai/jev","state":"x","questions":{"a":{"type":"text","instructions":"x"}}}`,
		"one option":      `{"model":"typesafe-ai/jev","state":"x","questions":{"a":{"type":"choice","instructions":"x","criteria":{"only":"1"}}}}`,
		"score as object": `{"model":"typesafe-ai/jev","state":"x","questions":{"a":{"type":"score","instructions":"x","criteria":{"lo":"l","hi":"h"}}}}`,
	}
	for name, body := range cases {
		decider := &fakeDecider{}
		status, _ := runDecide(t, decider, body)
		if status != 400 {
			t.Errorf("%s: status %d, want 400", name, status)
		}
		if decider.calls != 0 {
			t.Errorf("%s: reached the upstream model", name)
		}
	}
}

func TestDecideHostedReturnsTheVerifiedContractShape(t *testing.T) {
	decider := &fakeDecider{answers: map[string]decide.Answer{
		"refund": {Type: "boolean", Probability: pf(0.97)},
		"route":  {Type: "choice", Choice: ps("billing"), Probabilities: map[string]float64{"billing": 0.99, "shipping": 0.02}},
	}}
	status, body := runDecide(t, decider, decideBody)
	if status != 200 {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp struct {
		Model   string                   `json:"model"`
		Answers map[string]decide.Answer `json:"answers"`
		Usage   map[string]int           `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Model != "typesafe-ai/jev" || resp.Usage["inputTokens"] != 300 || resp.Usage["outputTokens"] != 20 {
		t.Fatalf("envelope: %s", body)
	}
	route := resp.Answers["route"].Probabilities
	if sum := route["billing"] + route["shipping"]; sum < 0.999999 || sum > 1.000001 {
		t.Fatalf("probabilities were not normalized by the second pass: %v", route)
	}
	if decider.seen.Model != "typesafe-ai/jev" || len(decider.seen.Questions) != 2 {
		t.Fatalf("upstream request: %+v", decider.seen)
	}
}

func TestDecideHostedNeverForwardsAnAnswerThatFailsTheSecondPass(t *testing.T) {
	violations := map[string]map[string]decide.Answer{
		"undeclared option": {
			"refund": {Type: "boolean", Probability: pf(0.9)},
			"route":  {Type: "choice", Choice: ps("legal"), Probabilities: map[string]float64{"billing": 0.5, "legal": 0.5}},
		},
		"missing question": {"refund": {Type: "boolean", Probability: pf(0.9)}},
		"probability over one": {
			"refund": {Type: "boolean", Probability: pf(7)},
			"route":  {Type: "choice", Choice: ps("billing"), Probabilities: map[string]float64{"billing": 1, "shipping": 0}},
		},
		"choice is not the argmax": {
			"refund": {Type: "boolean", Probability: pf(0.9)},
			"route":  {Type: "choice", Choice: ps("shipping"), Probabilities: map[string]float64{"billing": 0.9, "shipping": 0.1}},
		},
		"empty": {},
	}
	for name, answers := range violations {
		status, body := runDecide(t, &fakeDecider{answers: answers}, decideBody)
		if status != 502 {
			t.Errorf("%s: status %d, want 502", name, status)
		}
		if strings.Contains(body, `"answers"`) || strings.Contains(body, "legal") {
			t.Errorf("%s: an unverified answer reached the caller: %s", name, body)
		}
	}
}

func TestDecideHostedNeedsABuildThatSupportsIt(t *testing.T) {
	if status, _ := runDecide(t, chatOnlyClient{}, decideBody); status != 501 {
		t.Fatalf("status %d, want 501", status)
	}
}

func TestDecideNativeModelsRequireTheControlPlane(t *testing.T) {
	for model := range decide.NativeModels {
		body := strings.Replace(decideBody, "typesafe-ai/jev", model, 1)
		if status, _ := runDecide(t, &fakeDecider{}, body); status != 501 {
			t.Errorf("%s: status %d, want 501 without a control plane", model, status)
		}
	}
}

func TestNativeModelListIsPinned(t *testing.T) {
	// Mirrors NATIVE_DECISION_MODEL_PROVIDERS in the control plane's
	// catalog_data.py; change both together.
	want := map[string]string{
		decide.TrevModelID:             "cerebras,sambanova,fireworks,together",
		"google/gemini-3.1-flash-lite": "google-ai-studio",
		"openai/gpt-oss-20b":           "deepinfra",
		"google/gemma-4-e4b-it":        "deepinfra",
		"deepseek/deepseek-v4.1-flash": "deepinfra",
	}
	if len(decide.NativeModels) != len(want) {
		t.Fatalf("native models = %d, want %d", len(decide.NativeModels), len(want))
	}
	for model, providers := range want {
		if got := strings.Join(decide.NativeModels[model].Providers, ","); got != providers {
			t.Errorf("%s pinned to %q, want %q", model, got, providers)
		}
	}
}

func TestDecideHostedModelRejectsNativeOnlyOptions(t *testing.T) {
	// Jev has no thinking to turn on and one host. Ignoring the parameter
	// would let a caller believe it took effect.
	for param, fragment := range map[string]string{
		"reasoning":        `"reasoning":{"effort":"high"}`,
		"reasoning_effort": `"reasoning_effort":"high"`,
		"max_tokens":       `"max_tokens":4000`,
		"provider":         `"provider":{"only":["engy"]}`,
	} {
		decider := &fakeDecider{}
		body := strings.Replace(decideBody, `"state"`, fragment+`,"state"`, 1)
		status, payload := runDecide(t, decider, body)
		if status != 400 || !strings.Contains(payload, param) {
			t.Errorf("%s: status %d body %s", param, status, payload)
		}
		if decider.calls != 0 {
			t.Errorf("%s: the hosted model was called anyway", param)
		}
	}
}

func TestDecideAnyOtherModelTakesTheNativePath(t *testing.T) {
	// An untuned chat model is a native decision model too; without a control
	// plane that path refuses, which is how this proves the dispatch.
	body := strings.Replace(decideBody, "typesafe-ai/jev", "anthropic/claude-opus-5", 1)
	decider := &fakeDecider{}
	if status, _ := runDecide(t, decider, body); status != 501 {
		t.Fatalf("status %d, want 501 from the native path", status)
	}
	if decider.calls != 0 {
		t.Fatal("an ordinary chat model was sent to the hosted decision endpoint")
	}
	// Bad options are rejected before any call, tuned or not.
	bad := strings.Replace(body, `"state"`, `"max_tokens":3,"state"`, 1)
	if status, payload := runDecide(t, decider, bad); status != 400 || !strings.Contains(payload, "max_tokens") {
		t.Fatalf("max_tokens=3: status %d body %s", status, payload)
	}
}
