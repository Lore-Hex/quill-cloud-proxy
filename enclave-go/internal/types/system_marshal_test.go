package types

import (
	"encoding/json"
	"testing"
)

// TestAnthropicRequestMarshalSystemRaw verifies the system field is emitted from
// SystemRaw (content blocks preserving cache_control) when set, so providers that
// marshal the struct directly (Bedrock) forward system prompt-cache breakpoints.
func TestAnthropicRequestMarshalSystemRaw(t *testing.T) {
	req := AnthropicMessagesRequest{
		AnthropicVersion: "bedrock-2023-05-31",
		Messages:         []AnthropicMessage{{Role: "user", Content: "hi"}},
		MaxTokens:        16,
		System:           "flattened fallback",
		SystemRaw: []any{
			map[string]any{"type": "text", "text": "cached system", "cache_control": map[string]any{"type": "ephemeral"}},
		},
	}
	var out map[string]any
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sys, ok := out["system"].([]any)
	if !ok {
		t.Fatalf("system = %T (%v), want []any from SystemRaw; raw=%s", out["system"], out["system"], raw)
	}
	block := sys[0].(map[string]any)
	if block["cache_control"] == nil {
		t.Fatalf("system block missing cache_control: %s", raw)
	}
	// The flattened string must NOT leak alongside the raw blocks.
	if s, isStr := out["system"].(string); isStr {
		t.Fatalf("system emitted as string %q, want blocks", s)
	}
	// Sanity: other fields still marshal.
	if out["max_tokens"] != float64(16) {
		t.Fatalf("max_tokens = %v, want 16", out["max_tokens"])
	}
}

// TestAnthropicRequestMarshalSystemStringFallback verifies the common path is
// unchanged: no SystemRaw -> the flattened System string is emitted as before.
func TestAnthropicRequestMarshalSystemStringFallback(t *testing.T) {
	req := AnthropicMessagesRequest{
		AnthropicVersion: "bedrock-2023-05-31",
		Messages:         []AnthropicMessage{{Role: "user", Content: "hi"}},
		MaxTokens:        16,
		System:           "plain system",
	}
	var out map[string]any
	raw, _ := json.Marshal(req)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["system"] != "plain system" {
		t.Fatalf("system = %v, want \"plain system\"; raw=%s", out["system"], raw)
	}
}

// TestAnthropicRequestMarshalSystemOmitted verifies omitempty still drops the
// field when neither form is set.
func TestAnthropicRequestMarshalSystemOmitted(t *testing.T) {
	req := AnthropicMessagesRequest{
		AnthropicVersion: "bedrock-2023-05-31",
		Messages:         []AnthropicMessage{{Role: "user", Content: "hi"}},
		MaxTokens:        16,
	}
	var out map[string]any
	raw, _ := json.Marshal(req)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := out["system"]; present {
		t.Fatalf("system present but should be omitted: %s", raw)
	}
}
