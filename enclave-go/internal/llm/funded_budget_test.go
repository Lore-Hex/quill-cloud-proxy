package llm

import (
	"fmt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/testutil/fundedrequest"
	"testing"
)

func TestFundedInnerNativeAnthropicAndOpenAIWire(t *testing.T) {
	for _, total := range []int{1, 800, 1024, 1025, 8192, 32768, 60000} {
		for _, hint := range []any{map[string]any{"max_tokens": 32768}, map[string]any{"budget_tokens": 60000}, map[string]any{"thinking_budget": -1}, map[string]any{"effort": "high"}, true} {
			t.Run(fmt.Sprintf("%d/%v", total, hint), func(t *testing.T) {
				req, body, authorized := fundedrequest.New(t, total, hint, "")
				for _, model := range []string{"claude-haiku-4-5", "claude-opus-4-5", "claude-sonnet-4-6"} {
					native := anthropicChatReasoningBody(model, req, body)
					fundedrequest.Check(t, buildAnthropicWireRequest(model, native.Messages, native), authorized, false)
				}
				for _, model := range []string{"gpt-4o", "gpt-5"} {
					fundedrequest.Check(t, buildOpenAICompatibleRequest("openai", model, req, body, nil), authorized, false)
				}
			})
		}
	}
}

func TestFundedInnerPreservesAdaptiveEffort(t *testing.T) {
	req, body, authorized := fundedrequest.New(t, 8192, nil, "high")
	native := anthropicChatReasoningBody("claude-sonnet-4-6", req, body)
	if native.Thinking.(map[string]any)["type"] != "adaptive" {
		t.Fatalf("effort lost adaptive thinking: %#v", native.Thinking)
	}
	fundedrequest.Check(t, buildAnthropicWireRequest("claude-sonnet-4-6", native.Messages, native), authorized, false)
}
