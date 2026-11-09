package llm

import (
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// applyFireworksReasoningContract projects every accepted reasoning control
// onto Fireworks' chat-completions schema. That schema has no `reasoning`
// object (additionalProperties is false), its reasoning_effort enum is
// low/medium/high/xhigh/max/none/adaptive, and thinking.type=adaptive (like
// reasoning_effort=adaptive) is accepted only by MiniMax M3. Forwarding the
// OpenRouter reasoning object, Anthropic adaptive thinking, or an out-of-enum
// effort made Fireworks answer 400 invalid_request_error, and dropping
// output_config silently discarded the caller's effort.
func applyFireworksReasoningContract(provider, upstreamID string, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, wire *openAICompatibleRequest) {
	if normalizeDirectProvider(provider) != "fireworks" {
		return
	}
	adaptiveAllowed := fireworksAcceptsAdaptive(upstreamID)
	wire.ReasoningEffort = fireworksReasoningEffort(fireworksRequestedEffort(req, body), adaptiveAllowed)
	wire.Reasoning = nil

	mode := ""
	switch thinking := wire.Thinking.(type) {
	case map[string]string:
		mode = thinking["type"]
	case map[string]any:
		mode, _ = thinking["type"].(string)
	}
	if mode == "adaptive" && !adaptiveAllowed {
		// Other Fireworks model families reject adaptive. Its meaning (the
		// model decides how much to think, guided by effort) is carried by
		// reasoning_effort, or by the model default when no effort was given.
		wire.Thinking = nil
	}
	if wire.ReasoningEffort == "none" {
		// An explicit Off must not coexist with a thinking config that turns
		// reasoning back on; reasoning_effort=none is Fireworks' documented
		// switch for disabling reasoning.
		wire.Thinking = nil
	}
}

// fireworksRequestedEffort returns the caller's effort from, in order, an
// explicit reasoning.enabled=false, reasoning_effort / reasoning.effort, and
// native Messages output_config.effort.
func fireworksRequestedEffort(req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest) string {
	if req != nil {
		if values, ok := req.Reasoning.(map[string]any); ok {
			if enabled, present := values["enabled"].(bool); present && !enabled {
				return "none"
			}
		}
		if effort := chatReasoningEffort(req); effort != "" {
			return effort
		}
	}
	if body != nil {
		if config, ok := body.OutputConfig.(map[string]any); ok {
			effort, _ := config["effort"].(string)
			return effort
		}
	}
	return ""
}

// fireworksReasoningEffort maps an accepted effort onto Fireworks' enum. An
// empty result omits the field so Fireworks applies the model default.
func fireworksReasoningEffort(effort string, adaptiveAllowed bool) string {
	switch effort = strings.ToLower(strings.TrimSpace(effort)); effort {
	case "low", "medium", "high", "xhigh", "max", "none":
		return effort
	case "minimal":
		// Fireworks' smallest reasoning setting short of Off.
		return "low"
	case "off", "disable", "disabled":
		return "none"
	case "adaptive":
		if adaptiveAllowed {
			return effort
		}
		return ""
	default:
		// "auto" (and anything else) means "provider decides": omit it.
		return ""
	}
}

// fireworksAcceptsAdaptive reports whether the Fireworks model accepts the
// adaptive thinking mode. Fireworks documents this for MiniMax M3 only. The
// authorized upstream ID is accounts/fireworks/models/minimax-m3; the
// canonical minimax/minimax-m3 covers authorizations without one.
func fireworksAcceptsAdaptive(upstreamID string) bool {
	model := strings.ToLower(strings.TrimSpace(stripOpenRouterModelVariant(upstreamID)))
	if idx := strings.LastIndex(model, "/"); idx >= 0 {
		model = model[idx+1:]
	}
	return model == "minimax-m3" || strings.HasPrefix(model, "minimax-m3-")
}
