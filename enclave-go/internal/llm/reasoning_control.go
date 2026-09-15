package llm

import (
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func chatReasoningEffort(req *qtypes.OpenAIChatRequest) string {
	if req == nil {
		return ""
	}
	if value := strings.TrimSpace(req.ReasoningEffort); value != "" {
		return strings.ToLower(value)
	}
	values, _ := req.Reasoning.(map[string]any)
	value, _ := values["effort"].(string)
	return strings.ToLower(strings.TrimSpace(value))
}

func applyChatReasoningEffort(provider string, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, wire *openAICompatibleRequest) {
	effort := chatReasoningEffort(req)
	if effort == "" {
		return
	}
	// The shared Anthropic projection synthesizes a budget for old Claude
	// models. It is not a native thinking configuration for other providers.
	if body != nil && !body.NativeContent {
		if thinking, ok := wire.Thinking.(map[string]any); ok && thinking["budget_tokens"] != nil {
			wire.Thinking = nil
		}
	}
	switch normalizeDirectProvider(provider) {
	case "openai", "gemini", "google-ai-studio", "deepseek", "zai", "kimi", "mistral", "alibaba":
		wire.ReasoningEffort = effort
		wire.Reasoning = nil
	}
}

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
