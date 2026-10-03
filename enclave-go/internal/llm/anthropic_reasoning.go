package llm

import (
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"

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
	model = strings.ReplaceAll(strings.ToLower(model), ".", "-")
	manual := strings.Contains(model, "claude-opus-4-5")
	adaptive := false
	for _, prefix := range []string{"claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8", "claude-opus-5", "claude-sonnet-4-6", "claude-sonnet-5", "claude-fable-5"} {
		if strings.Contains(model, prefix) {
			adaptive = true
			break
		}
	}
	if effort == "" {
		// A body whose thinking is already configured keeps its own limit.
		if adaptive && body.Thinking == nil && anthropicThinkingDefaultCapApplies(req, body) {
			result := *body
			result.AnthropicMaxTokens = AnthropicThinkingDefaultMaxTokens
			return &result
		}
		return body
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
		if anthropicThinkingDefaultCapApplies(req, body) {
			result.AnthropicMaxTokens = AnthropicThinkingDefaultMaxTokens
		}
		result.Temperature = nil
		result.TopP = nil
	}
	return &result
}

// AnthropicThinkingDefaultMaxTokens is the output ceiling sent to a model that
// thinks adaptively when the caller set none. adapter.DefaultMaxTokens (4096)
// is a wire requirement, not a choice, and it counts thinking: a high-effort
// Opus 5.5 turn spent all 4096 thinking and was cut off (AnyEval Terminal-Bench
// 4.0, 2026-10-02). OpenAI-compatible upstreams already omit the cap entirely.
// 32000 is within every listed model's output maximum; upstream calls stream.
// Authorization is unchanged: an uncapped request is still estimated at 512.
const AnthropicThinkingDefaultMaxTokens = 32000

// anthropicThinkingDefaultCapApplies is true only for a caller that set no cap
// and no funded orchestration allowance, on a body still at the wire default.
// An adapter-derived AnthropicMaxTokens (budget + default) is not a caller cap:
// adaptive dispatch discards it, and an explicit caller budget returns earlier.
func anthropicThinkingDefaultCapApplies(req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest) bool {
	return !body.MaxTokensExplicit && req.InternalOutputTokenLimit <= 0 &&
		body.MaxTokens == adapter.DefaultMaxTokens
}
