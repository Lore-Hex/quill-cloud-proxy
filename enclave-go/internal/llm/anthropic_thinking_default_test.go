package llm

import (
	"encoding/json"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// wireMaxTokens builds the direct Anthropic wire body for a chat request, the
// same projection Bedrock and Vertex read through AnthropicDispatchMaxTokens.
func wireMaxTokens(t *testing.T, model string, req *qtypes.OpenAIChatRequest) (float64, map[string]any) {
	t.Helper()
	req.Model = model
	req.Messages = []qtypes.OpenAIChatMessage{{Role: "user", Content: "Think hard."}}
	body, err := adapter.ToAnthropic(req, model)
	if err != nil {
		t.Fatal(err)
	}
	before := *body
	native := anthropicChatReasoningBody(model, req, body)
	if body.AnthropicMaxTokens != before.AnthropicMaxTokens || body.MaxTokens != before.MaxTokens {
		t.Fatal("mutated the shared fallback body")
	}
	raw, err := json.Marshal(buildAnthropicWireRequest(model, native.Messages, native))
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	return wire["max_tokens"].(float64), wire
}

func TestUncappedThinkingModelGetsTheThinkingDefault(t *testing.T) {
	for _, model := range []string{"claude-opus-5-5", "claude-opus-4.8", "claude-sonnet-5", "claude-fable-5-1"} {
		for _, effort := range []string{"", "low", "high", "xhigh", "max"} {
			got, wire := wireMaxTokens(t, model, &qtypes.OpenAIChatRequest{ReasoningEffort: effort})
			if got != AnthropicThinkingDefaultMaxTokens {
				t.Errorf("%s effort=%q max_tokens=%v, want %d", model, effort, got, AnthropicThinkingDefaultMaxTokens)
			}
			// No effort keeps the provider's own thinking default: nothing added.
			if effort == "" && (wire["thinking"] != nil || wire["output_config"] != nil) {
				t.Errorf("%s no effort grew thinking=%v output_config=%v", model, wire["thinking"], wire["output_config"])
			}
		}
	}
}

func TestCallerCapsAndNonThinkingRequestsKeepTheirLimit(t *testing.T) {
	explicit := 1000
	explicitDefault := adapter.DefaultMaxTokens // a caller who asked for exactly 4096
	cases := []struct {
		name  string
		model string
		req   *qtypes.OpenAIChatRequest
		want  float64
	}{
		{"explicit cap", "claude-opus-5-5", &qtypes.OpenAIChatRequest{MaxTokens: &explicit, ReasoningEffort: "xhigh"}, 1000},
		{"explicit cap, no effort", "claude-opus-5-5", &qtypes.OpenAIChatRequest{MaxTokens: &explicit}, 1000},
		{"explicit 4096", "claude-opus-5-5", &qtypes.OpenAIChatRequest{MaxTokens: &explicitDefault}, float64(adapter.DefaultMaxTokens)},
		{"explicit 4096 with effort", "claude-opus-5-5", &qtypes.OpenAIChatRequest{MaxTokens: &explicitDefault, ReasoningEffort: "high"}, float64(adapter.DefaultMaxTokens)},
		{"thinking off", "claude-opus-5-5", &qtypes.OpenAIChatRequest{ReasoningEffort: "none"}, float64(adapter.DefaultMaxTokens)},
		{"thinking disabled flag", "claude-opus-5-5", &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"enabled": false}}, float64(adapter.DefaultMaxTokens)},
		{"non-thinking model", "claude-haiku-4-5", &qtypes.OpenAIChatRequest{}, float64(adapter.DefaultMaxTokens)},
		{"manual-budget model, no effort", "claude-opus-4-5", &qtypes.OpenAIChatRequest{}, float64(adapter.DefaultMaxTokens)},
	}
	for _, c := range cases {
		if got, _ := wireMaxTokens(t, c.model, c.req); got != c.want {
			t.Errorf("%s: max_tokens=%v want %v", c.name, got, c.want)
		}
	}
}

func TestFundedInnerCallsKeepTheirAllowance(t *testing.T) {
	// An orchestration allowance is authorized output; the default never widens it.
	req := &qtypes.OpenAIChatRequest{InternalOutputTokenLimit: 6000}
	if got, _ := wireMaxTokens(t, "claude-opus-5-5", req); got != float64(adapter.DefaultMaxTokens) {
		t.Fatalf("funded inner call max_tokens=%v", got)
	}
}

func TestConfiguredThinkingWithoutEffortKeepsItsLimit(t *testing.T) {
	body := &qtypes.AnthropicMessagesRequest{MaxTokens: adapter.DefaultMaxTokens,
		Thinking: map[string]any{"type": "enabled", "budget_tokens": 1024}}
	if got := anthropicChatReasoningBody("claude-sonnet-4-6", &qtypes.OpenAIChatRequest{}, body); got.AnthropicDispatchMaxTokens() != adapter.DefaultMaxTokens {
		t.Fatalf("configured thinking body max_tokens=%d", got.AnthropicDispatchMaxTokens())
	}
}

func TestDirectlyBuiltBodiesKeepANonDefaultLimit(t *testing.T) {
	// Internal callers build bodies directly; a limit they chose is not the wire default.
	body := &qtypes.AnthropicMessagesRequest{MaxTokens: 2048}
	for _, effort := range []string{"", "high"} {
		got := anthropicChatReasoningBody("claude-opus-5-5", &qtypes.OpenAIChatRequest{ReasoningEffort: effort}, body)
		if got.AnthropicDispatchMaxTokens() != 2048 {
			t.Fatalf("effort=%q max_tokens=%d", effort, got.AnthropicDispatchMaxTokens())
		}
	}
}

func TestNativeMessagesBodiesAreUntouched(t *testing.T) {
	body := &qtypes.AnthropicMessagesRequest{NativeContent: true, MaxTokens: adapter.DefaultMaxTokens}
	if anthropicChatReasoningBody("claude-opus-5-5", &qtypes.OpenAIChatRequest{}, body) != body {
		t.Fatal("reinterpreted a native Messages body")
	}
}
