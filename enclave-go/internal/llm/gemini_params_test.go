package llm

import (
	"encoding/json"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func geminiParamsWire(t *testing.T, model string, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest) map[string]any {
	t.Helper()
	got := buildOpenAICompatibleRequest("google-ai-studio", model, req, body, []chatMessage{{Role: "user", Content: "Reply PONG"}})
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestGeminiThinkingBudgetBecomesThinkingLevel(t *testing.T) {
	cases := []struct {
		name   string
		model  string
		req    *qtypes.OpenAIChatRequest
		body   *qtypes.AnthropicMessagesRequest
		effort string
	}{
		{
			name:   "reasoning.max_tokens",
			model:  "gemini-3.8-flash",
			req:    &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"max_tokens": float64(8192), "exclude": true}},
			body:   &qtypes.AnthropicMessagesRequest{},
			effort: "high",
		},
		{
			name:   "reasoning.thinking_budget zero",
			model:  "gemini-3.6-flash",
			req:    &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"thinking_budget": 0}},
			body:   &qtypes.AnthropicMessagesRequest{},
			effort: "low",
		},
		{
			name:   "anthropic thinking budget",
			model:  "gemini-3.7-flash",
			req:    &qtypes.OpenAIChatRequest{},
			body:   &qtypes.AnthropicMessagesRequest{NativeContent: true, Thinking: map[string]any{"type": "enabled", "budget_tokens": 4096}},
			effort: "high",
		},
		{
			name:   "anthropic thinking disabled",
			model:  "gemini-3.1-pro-preview",
			req:    &qtypes.OpenAIChatRequest{},
			body:   &qtypes.AnthropicMessagesRequest{NativeContent: true, Thinking: map[string]any{"type": "disabled"}},
			effort: "low",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := geminiParamsWire(t, tc.model, tc.req, tc.body)
			if wire["reasoning_effort"] != tc.effort {
				t.Fatalf("reasoning_effort = %#v, want %q (wire %#v)", wire["reasoning_effort"], tc.effort, wire)
			}
			if _, ok := wire["thinking"]; ok {
				t.Fatalf("thinking forwarded: %#v", wire["thinking"])
			}
			encoded, _ := json.Marshal(wire)
			for _, key := range geminiThinkingBudgetKeys {
				if strings.Contains(string(encoded), `"`+key+`"`) && key != "max_tokens" {
					t.Fatalf("budget key %q forwarded: %s", key, encoded)
				}
			}
			if reasoning, ok := wire["reasoning"].(map[string]any); ok {
				if _, has := reasoning["max_tokens"]; has {
					t.Fatalf("reasoning.max_tokens forwarded: %#v", reasoning)
				}
			}
		})
	}
}

func TestGeminiExplicitEffortWinsOverBudget(t *testing.T) {
	wire := geminiParamsWire(t, "gemini-3.8-flash",
		&qtypes.OpenAIChatRequest{ReasoningEffort: "medium", Reasoning: map[string]any{"max_tokens": 100}},
		&qtypes.AnthropicMessagesRequest{})
	if wire["reasoning_effort"] != "medium" {
		t.Fatalf("reasoning_effort = %#v, want medium", wire["reasoning_effort"])
	}
}

func TestGeminiBudgetTranslationDoesNotMutateCaller(t *testing.T) {
	original := map[string]any{"max_tokens": float64(2048)}
	geminiParamsWire(t, "gemini-3.8-flash", &qtypes.OpenAIChatRequest{Reasoning: original}, &qtypes.AnthropicMessagesRequest{})
	if original["max_tokens"] != float64(2048) {
		t.Fatalf("caller reasoning mutated: %#v", original)
	}
}

func TestGeminiSamplingParametersDroppedFrom36(t *testing.T) {
	temperature, topP, topK := 0.2, 0.9, 40
	body := func() *qtypes.AnthropicMessagesRequest {
		return &qtypes.AnthropicMessagesRequest{Temperature: &temperature, TopP: &topP, TopK: &topK}
	}
	for _, model := range []string{"gemini-3.6-flash", "gemini-3.7-flash", "gemini-3.8-flash", "gemini-4.0-pro"} {
		wire := geminiParamsWire(t, model, &qtypes.OpenAIChatRequest{}, body())
		for _, key := range []string{"temperature", "top_p", "top_k"} {
			if _, ok := wire[key]; ok {
				t.Fatalf("%s: %s forwarded: %#v", model, key, wire[key])
			}
		}
	}
	for _, model := range []string{"gemini-2.5-flash", "gemini-3.5-flash", "gemma-4-31b-it"} {
		wire := geminiParamsWire(t, model, &qtypes.OpenAIChatRequest{}, body())
		for _, key := range []string{"temperature", "top_p", "top_k"} {
			if _, ok := wire[key]; !ok {
				t.Fatalf("%s: %s dropped but the model still accepts it", model, key)
			}
		}
	}
}

func TestGeminiContractLeavesOtherProvidersAndOlderGeminiAlone(t *testing.T) {
	thinking := map[string]any{"type": "enabled", "budget_tokens": 4096}
	other := buildOpenAICompatibleRequest("deepinfra", "gemini-3.8-flash",
		&qtypes.OpenAIChatRequest{}, &qtypes.AnthropicMessagesRequest{NativeContent: true, Thinking: thinking}, nil)
	if other.Thinking == nil {
		t.Fatal("non-Google provider lost its thinking field")
	}
	older := buildOpenAICompatibleRequest("google-ai-studio", "gemini-2.5-flash",
		&qtypes.OpenAIChatRequest{Reasoning: map[string]any{"max_tokens": 1024}}, &qtypes.AnthropicMessagesRequest{}, nil)
	if reasoning, _ := older.Reasoning.(map[string]any); reasoning["max_tokens"] == nil {
		t.Fatalf("Gemini 2.5 budget removed: %#v", older.Reasoning)
	}
}

func TestGeminiMajorOnlyModelIDsAreTranslated(t *testing.T) {
	for _, model := range []string{"gemini-3-flash-preview", "gemini-3-pro-preview"} {
		wire := geminiParamsWire(t, model,
			&qtypes.OpenAIChatRequest{Reasoning: map[string]any{"max_tokens": float64(8192)}},
			&qtypes.AnthropicMessagesRequest{NativeContent: true, Thinking: map[string]any{"type": "enabled", "budget_tokens": 8192}})
		if wire["reasoning_effort"] != "high" {
			t.Fatalf("%s: reasoning_effort = %#v, want high", model, wire["reasoning_effort"])
		}
		if _, ok := wire["thinking"]; ok {
			t.Fatalf("%s: thinking forwarded", model)
		}
		if _, ok := wire["reasoning"]; ok {
			t.Fatalf("%s: reasoning budget forwarded: %#v", model, wire["reasoning"])
		}
	}
	if !geminiVersionAtLeast("gemini-3-flash-preview", 3, 0) || geminiVersionAtLeast("gemini-3-flash-preview", 3, 6) {
		t.Fatal("major-only Gemini 3 must parse as 3.0")
	}
	if geminiVersionAtLeast("gemma-4-31b-it", 3, 0) {
		t.Fatal("Gemma must not parse as Gemini")
	}
}
