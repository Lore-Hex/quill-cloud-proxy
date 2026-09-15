package llm

import (
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Resolve effort at dispatch, after fallback has selected the actual model.
// Never mutate the shared request body or reinterpret native Messages input.
func anthropicChatReasoningBody(model string, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest) *qtypes.AnthropicMessagesRequest {
	if req == nil || body == nil || body.NativeContent {
		return body
	}
	effort := chatReasoningEffort(req)
	if values, ok := req.Reasoning.(map[string]any); ok {
		if enabled, present := values["enabled"].(bool); present && !enabled {
			effort = "none"
		}
	}
	if effort == "" {
		return body
	}
	model = strings.ReplaceAll(strings.ToLower(model), ".", "-")
	manual := strings.Contains(model, "claude-opus-4-5")
	adaptive := false
	for _, prefix := range []string{"claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8", "claude-opus-5", "claude-sonnet-4-6", "claude-sonnet-5", "claude-fable-5"} {
		if strings.Contains(model, prefix) {
			adaptive = true
			break
		}
	}
	if !manual && !adaptive {
		return body
	}
	result := *body
	// Keep format and other native output controls while adding effort.
	config := map[string]any{}
	if original, ok := body.OutputConfig.(map[string]any); ok {
		for key, value := range original {
			config[key] = value
		}
	}
	if effort == "none" {
		result.Thinking = map[string]any{"type": "disabled"}
		result.AnthropicMaxTokens = 0
		return &result
	}
	config["effort"] = effort
	result.OutputConfig = config
	// An explicit caller budget still takes precedence over an effort-derived
	// thinking mode. The provider validates whether its model accepts budgets.
	if values, ok := req.Reasoning.(map[string]any); ok && values["max_tokens"] != nil {
		return &result
	}
	if adaptive {
		result.Thinking = map[string]any{"type": "adaptive"}
		result.AnthropicMaxTokens = 0
		result.Temperature = nil
		result.TopP = nil
	}
	return &result
}
