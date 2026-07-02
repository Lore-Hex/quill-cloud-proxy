package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// TestApplyCustomModelPromptKeepsSystemInSyncWithSystemRaw guards the P1
// regression: when a custom-model request carries a system cache_control
// breakpoint (SystemRaw set), the hidden prompt must be prepended to BOTH the
// raw blocks AND the flattened System string. Upstreams that read only
// body.System (OpenAI-compatible / Vertex / OpenRouter / Bedrock) would
// otherwise drop the custom model's hidden prompt for cache_control requests.
func TestApplyCustomModelPromptKeepsSystemInSyncWithSystemRaw(t *testing.T) {
	authz := &trustedrouter.Authorization{
		CustomModel: &trustedrouter.CustomModel{HiddenPrompt: "HIDDEN_PROMPT"},
	}
	anthropicReq := &types.AnthropicMessagesRequest{
		System: "user system",
		SystemRaw: []any{
			map[string]any{"type": "text", "text": "user system", "cache_control": map[string]any{"type": "ephemeral"}},
		},
	}
	req := &types.OpenAIChatRequest{
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}},
	}

	applyCustomModelPromptToMessages(req, anthropicReq, authz)

	// P1: flattened System must carry the hidden prompt for string-only upstreams.
	if !strings.Contains(anthropicReq.System, "HIDDEN_PROMPT") {
		t.Fatalf("System = %q, want the hidden prompt prepended", anthropicReq.System)
	}
	if !strings.Contains(anthropicReq.System, "user system") {
		t.Fatalf("System = %q, want the original system retained", anthropicReq.System)
	}
	// SystemRaw must also carry the hidden prompt AND keep the client's cache_control.
	raw, _ := json.Marshal(anthropicReq.SystemRaw)
	if !strings.Contains(string(raw), "HIDDEN_PROMPT") {
		t.Fatalf("SystemRaw missing hidden prompt: %s", raw)
	}
	if !strings.Contains(string(raw), "cache_control") {
		t.Fatalf("SystemRaw dropped cache_control: %s", raw)
	}
}

// TestApplyCustomModelPromptStringSystemUnchanged locks in the non-cache path:
// with no SystemRaw the hidden prompt is prepended to the System string as before.
func TestApplyCustomModelPromptStringSystemUnchanged(t *testing.T) {
	authz := &trustedrouter.Authorization{
		CustomModel: &trustedrouter.CustomModel{HiddenPrompt: "HIDDEN_PROMPT"},
	}
	anthropicReq := &types.AnthropicMessagesRequest{System: "user system"}
	req := &types.OpenAIChatRequest{Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}}}

	applyCustomModelPromptToMessages(req, anthropicReq, authz)

	if anthropicReq.SystemRaw != nil {
		t.Fatalf("SystemRaw = %v, want nil (no breakpoint)", anthropicReq.SystemRaw)
	}
	if anthropicReq.System != "HIDDEN_PROMPT\n\nuser system" {
		t.Fatalf("System = %q, want hidden prompt prepended", anthropicReq.System)
	}
}
