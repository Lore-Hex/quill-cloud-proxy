package llm

import (
	"encoding/json"
	"strings"
)

// Google's Gemini parameter deprecation (AI Studio notice, 2026-10-06):
// Gemini 3 models remap a numeric thinking_budget onto thinking_level today,
// but upcoming models reject it with 400 INVALID_ARGUMENT. Since Gemini 3.6
// Flash, temperature, top_p and top_k have had no effect, and upcoming models
// reject them too. Translate before the request leaves the enclave so callers
// that send OpenRouter-style budgets or sampling values keep working.

var geminiThinkingBudgetKeys = []string{"max_tokens", "thinking_budget", "budget_tokens"}

func isGoogleGeminiProvider(provider string) bool {
	switch normalizeDirectProvider(provider) {
	case "gemini", "google-ai-studio":
		return true
	}
	return false
}

// geminiDropsSamplingParameters reports models whose sampling is fixed.
func geminiDropsSamplingParameters(modelID string) bool {
	return geminiVersionAtLeast(modelID, 3, 6)
}

// geminiThinkingLevelForBudget mirrors the native generateContent mapping:
// a zero budget asks for the least thinking, any other budget for the most.
func geminiThinkingLevelForBudget(budget int) string {
	if budget == 0 {
		return "low"
	}
	return "high"
}

// applyGeminiParameterContract rewrites an OpenAI-compatible request bound for
// Google's Gemini endpoint. Gemma and other non-Gemini models are untouched.
func applyGeminiParameterContract(provider, modelID string, wire *openAICompatibleRequest) {
	if wire == nil || !isGoogleGeminiProvider(provider) || !geminiVersionAtLeast(modelID, 3, 0) {
		return
	}
	budget, hasBudget := geminiWireThinkingBudget(wire)
	wire.Thinking = nil
	wire.Reasoning = geminiReasoningWithoutBudget(wire.Reasoning)
	if hasBudget && strings.TrimSpace(wire.ReasoningEffort) == "" && geminiReasoningEffortField(wire.Reasoning) == "" {
		wire.ReasoningEffort = geminiThinkingLevelForBudget(budget)
	}
	if geminiDropsSamplingParameters(modelID) {
		wire.Temperature = nil
		wire.TopP = nil
		wire.TopK = nil
	}
}

func geminiWireThinkingBudget(wire *openAICompatibleRequest) (int, bool) {
	if values, ok := wire.Reasoning.(map[string]any); ok {
		for _, key := range geminiThinkingBudgetKeys {
			if n, ok := vertexGeminiToInt(values[key]); ok {
				return n, true
			}
		}
	}
	if thinking, ok := wire.Thinking.(map[string]any); ok {
		if typ, _ := thinking["type"].(string); strings.EqualFold(typ, "disabled") {
			return 0, true
		}
		if n, ok := vertexGeminiToInt(thinking["budget_tokens"]); ok {
			return n, true
		}
	}
	return 0, false
}

func geminiReasoningWithoutBudget(reasoning any) any {
	values, ok := reasoning.(map[string]any)
	if !ok {
		return reasoning
	}
	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = value
	}
	for _, key := range geminiThinkingBudgetKeys {
		delete(result, key)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func geminiReasoningEffortField(reasoning any) string {
	values, ok := reasoning.(map[string]any)
	if !ok {
		return ""
	}
	effort, _ := values["effort"].(string)
	return strings.TrimSpace(effort)
}

func vertexGeminiToInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i), true
		}
	}
	return 0, false
}
