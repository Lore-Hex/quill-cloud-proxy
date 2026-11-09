package llm

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	fireworksQwenMax   = "accounts/fireworks/models/qwen3p8-max"
	fireworksMiniMaxM3 = "accounts/fireworks/models/minimax-m3"
)

// fireworksChatWire runs a chat-completions payload through the same request
// validation and Anthropic projection the enclave uses, then builds the
// Fireworks wire body.
func fireworksChatWire(t *testing.T, upstreamID, payload string) map[string]any {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &raw); err != nil {
		t.Fatal(err)
	}
	validation, err := adapter.ValidateChatRequestFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	var req qtypes.OpenAIChatRequest
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatal(err)
	}
	if validation.ReasoningAlias != nil {
		req.Reasoning = validation.ReasoningAlias
	}
	body, err := adapter.ToAnthropic(&req, req.Model)
	if err != nil {
		t.Fatal(err)
	}
	return encodeWire(t, buildOpenAICompatibleRequest("fireworks", upstreamID, &req, body, nil))
}

// fireworksNativeWire does the same for a native /v1/messages payload.
func fireworksNativeWire(t *testing.T, upstreamID, payload string) map[string]any {
	t.Helper()
	var request adapter.AnthropicNativeRequest
	if err := json.Unmarshal([]byte(payload), &request); err != nil {
		t.Fatal(err)
	}
	body, err := adapter.MessagesToAnthropic(&request)
	if err != nil {
		t.Fatal(err)
	}
	req := adapter.MessagesToChatShim(&request)
	return encodeWire(t, buildOpenAICompatibleRequest("fireworks", upstreamID, req, body, nil))
}

func encodeWire(t *testing.T, wire openAICompatibleRequest) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestFireworksChatReasoningWire(t *testing.T) {
	const prefix = `{"model":"qwen/qwen3.8-max","messages":[{"role":"user","content":"Reply OK"}],`
	cases := []struct {
		name     string
		model    string
		fields   string
		effort   any // nil = reasoning_effort omitted
		thinking any // nil = thinking omitted
	}{
		{"reasoning object effort becomes top-level", fireworksQwenMax, `"reasoning":{"effort":"high"}`, "high", nil},
		{"reasoning object xhigh", fireworksQwenMax, `"reasoning":{"effort":"xhigh"}`, "xhigh", nil},
		{"reasoning object none", fireworksQwenMax, `"reasoning":{"effort":"none"}`, "none", nil},
		{"enabled false is none", fireworksQwenMax, `"reasoning":{"enabled":false}`, "none", nil},
		{"enabled false beats effort", fireworksQwenMax, `"reasoning":{"enabled":false,"effort":"high"}`, "none", nil},
		{"reasoning_effort passes through", fireworksQwenMax, `"reasoning_effort":"medium"`, "medium", nil},
		{"reasoning_effort max", fireworksQwenMax, `"reasoning_effort":"max"`, "max", nil},
		{"minimal clamps to low", fireworksQwenMax, `"reasoning_effort":"minimal"`, "low", nil},
		{"nested minimal clamps to low", fireworksQwenMax, `"reasoning":{"effort":"minimal"}`, "low", nil},
		{"auto is omitted", fireworksQwenMax, `"reasoning_effort":"auto"`, nil, nil},
		{"nested auto is omitted", fireworksQwenMax, `"reasoning":{"effort":"auto"}`, nil, nil},
		{"output_config effort", fireworksQwenMax, `"output_config":{"effort":"high"}`, "high", nil},
		{"adaptive thinking plus output_config", fireworksQwenMax, `"thinking":{"type":"adaptive"},"output_config":{"effort":"low"}`, "low", nil},
		{"adaptive thinking plus output_config on MiniMax M3", fireworksMiniMaxM3, `"thinking":{"type":"adaptive"},"output_config":{"effort":"max"}`, "max", nil},
		{"enable_thinking false is none", fireworksQwenMax, `"enable_thinking":false`, "none", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := fireworksChatWire(t, tc.model, prefix+tc.fields+`}`)
			if _, present := wire["reasoning"]; present {
				t.Fatalf("reasoning object reached Fireworks: %#v", wire["reasoning"])
			}
			if !reflect.DeepEqual(wire["reasoning_effort"], tc.effort) {
				t.Fatalf("reasoning_effort = %#v, want %#v (wire %#v)", wire["reasoning_effort"], tc.effort, wire)
			}
			if !reflect.DeepEqual(wire["thinking"], tc.thinking) {
				t.Fatalf("thinking = %#v, want %#v", wire["thinking"], tc.thinking)
			}
			if wire["model"] != tc.model {
				t.Fatalf("model = %#v", wire["model"])
			}
		})
	}
}

func TestFireworksNativeMessagesReasoningWire(t *testing.T) {
	const prefix = `{"model":"qwen/qwen3.8-max","max_tokens":4096,"messages":[{"role":"user","content":"Reply OK"}]`
	adaptive := map[string]any{"type": "adaptive"}
	cases := []struct {
		name     string
		model    string
		fields   string
		effort   any
		thinking any
	}{
		// The QUILL-ROUTER-FM shape: adaptive thinking was forwarded to a
		// model family that rejects it, and the effort was dropped.
		{"adaptive plus output_config", fireworksQwenMax, `,"thinking":{"type":"adaptive"},"output_config":{"effort":"high"}`, "high", nil},
		{"adaptive without effort", fireworksQwenMax, `,"thinking":{"type":"adaptive"}`, nil, nil},
		{"MiniMax M3 keeps adaptive", fireworksMiniMaxM3, `,"thinking":{"type":"adaptive"},"output_config":{"effort":"medium"}`, "medium", adaptive},
		{"canonical MiniMax M3 id keeps adaptive", "minimax/minimax-m3", `,"thinking":{"type":"adaptive"}`, nil, adaptive},
		{"output_config only", fireworksQwenMax, `,"output_config":{"effort":"xhigh"}`, "xhigh", nil},
		{"enabled budget kept", fireworksQwenMax, `,"thinking":{"type":"enabled","budget_tokens":2048}`, nil, map[string]any{"type": "enabled", "budget_tokens": float64(2048)}},
		{"disabled kept", fireworksQwenMax, `,"thinking":{"type":"disabled"}`, nil, map[string]any{"type": "disabled"}},
		{"no reasoning controls", fireworksQwenMax, ``, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := fireworksNativeWire(t, tc.model, prefix+tc.fields+`}`)
			if _, present := wire["reasoning"]; present {
				t.Fatalf("reasoning object reached Fireworks: %#v", wire["reasoning"])
			}
			if _, present := wire["output_config"]; present {
				t.Fatalf("output_config reached Fireworks: %#v", wire["output_config"])
			}
			if !reflect.DeepEqual(wire["reasoning_effort"], tc.effort) {
				t.Fatalf("reasoning_effort = %#v, want %#v (wire %#v)", wire["reasoning_effort"], tc.effort, wire)
			}
			if !reflect.DeepEqual(wire["thinking"], tc.thinking) {
				t.Fatalf("thinking = %#v, want %#v", wire["thinking"], tc.thinking)
			}
		})
	}
}

func TestFireworksReasoningEffortEnum(t *testing.T) {
	cases := []struct {
		in       string
		adaptive bool
		want     string
	}{
		{"low", false, "low"}, {"medium", false, "medium"}, {"high", false, "high"},
		{"xhigh", false, "xhigh"}, {"max", false, "max"}, {"none", false, "none"},
		{"HIGH", false, "high"}, {" minimal ", false, "low"},
		{"off", false, "none"}, {"disabled", false, "none"}, {"disable", false, "none"},
		{"auto", false, ""}, {"", false, ""}, {"bogus", false, ""},
		{"adaptive", false, ""}, {"adaptive", true, "adaptive"},
	}
	for _, tc := range cases {
		if got := fireworksReasoningEffort(tc.in, tc.adaptive); got != tc.want {
			t.Errorf("fireworksReasoningEffort(%q, %t) = %q, want %q", tc.in, tc.adaptive, got, tc.want)
		}
	}
}

func TestFireworksAcceptsAdaptive(t *testing.T) {
	for model, want := range map[string]bool{
		"accounts/fireworks/models/minimax-m3":   true,
		"minimax/minimax-m3":                     true,
		"MiniMax-M3":                             true,
		"accounts/fireworks/models/minimax-m2p7": false,
		"accounts/fireworks/models/qwen3p8-max":  false,
		"accounts/fireworks/models/minimax-m30":  false,
		"accounts/fireworks/models/kimi-k3":      false,
		"":                                       false,
	} {
		if got := fireworksAcceptsAdaptive(model); got != want {
			t.Errorf("fireworksAcceptsAdaptive(%q) = %t, want %t", model, got, want)
		}
	}
}

func TestFireworksContractLeavesOtherProvidersAlone(t *testing.T) {
	req := &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"type": "adaptive"}}
	body := &qtypes.AnthropicMessagesRequest{NativeContent: true, Thinking: map[string]any{"type": "adaptive"}, OutputConfig: map[string]any{"effort": "high"}}
	for _, provider := range []string{"deepinfra", "together", "openrouter"} {
		wire := buildOpenAICompatibleRequest(provider, "qwen/qwen3.8-max", req, body, nil)
		if !reflect.DeepEqual(wire.Thinking, map[string]any{"type": "adaptive"}) || wire.Reasoning == nil || wire.ReasoningEffort != "" {
			t.Errorf("%s wire changed: thinking=%#v reasoning=%#v effort=%q", provider, wire.Thinking, wire.Reasoning, wire.ReasoningEffort)
		}
	}
}
