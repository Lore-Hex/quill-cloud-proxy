package llm

import qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"

// Native hybrid-model switches are not OpenAI reasoning objects or Anthropic
// token budgets. In particular, forwarding enabled:false unchanged can be
// silently ignored by a direct provider and leave thinking on.
func applyHybridReasoningControl(provider string, req *qtypes.OpenAIChatRequest, wire *openAICompatibleRequest) {
	if req == nil {
		return
	}
	switch normalizeDirectProvider(provider) {
	case "zai", "deepseek", "kimi":
	default:
		return
	}
	values, ok := req.Reasoning.(map[string]any)
	if !ok {
		return
	}
	enabled, explicit := values["enabled"].(bool)
	if !explicit {
		return
	}
	mode := "disabled"
	if enabled {
		mode = "enabled"
	}
	wire.Thinking = map[string]string{"type": mode}
	wire.Reasoning = nil
	// An explicit Off cannot coexist with an effort that turns thinking back
	// on. On keeps a separately supplied effort for providers that accept it.
	if !enabled {
		wire.ReasoningEffort = ""
	}
}

func explicitHybridThinkingConflict(provider string, req *qtypes.OpenAIChatRequest, wire openAICompatibleRequest) bool {
	if normalizeDirectProvider(provider) != "kimi" || req == nil {
		return false
	}
	values, _ := req.Reasoning.(map[string]any)
	enabled, _ := values["enabled"].(bool)
	thinking, _ := wire.Thinking.(map[string]string)
	return enabled && thinking["type"] == "disabled"
}
