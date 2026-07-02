package adapter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// TestToAnthropicSystemCacheControlSetsSystemRaw verifies a chat system message
// carrying a cache_control breakpoint is promoted to Anthropic system content
// blocks (SystemRaw) preserving the marker, while the flattened System string
// still holds the text for token estimation / string-only upstreams.
func TestToAnthropicSystemCacheControlSetsSystemRaw(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Model: "anthropic/claude-haiku-4.5",
		Messages: []types.OpenAIChatMessage{
			{Role: "system", Content: []any{
				map[string]any{"type": "text", "text": "large cached system prefix", "cache_control": map[string]any{"type": "ephemeral"}},
			}},
			{Role: "user", Content: "hi"},
		},
	}
	body, err := ToAnthropic(req, "")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	if body.SystemRaw == nil {
		t.Fatalf("SystemRaw is nil, want promoted system blocks")
	}
	raw, _ := json.Marshal(body.SystemRaw)
	if !strings.Contains(string(raw), `"cache_control"`) || !strings.Contains(string(raw), "ephemeral") {
		t.Fatalf("SystemRaw dropped cache_control: %s", raw)
	}
	if !strings.Contains(string(raw), "large cached system prefix") {
		t.Fatalf("SystemRaw missing system text: %s", raw)
	}
	if body.System != "large cached system prefix" {
		t.Fatalf("System string = %q, want the flattened text", body.System)
	}
}

// TestToAnthropicSystemWithoutCacheControlNoSystemRaw verifies the common case
// is unchanged: a plain string system prompt (no breakpoint) leaves SystemRaw
// nil so the field is sent as a bare string.
func TestToAnthropicSystemWithoutCacheControlNoSystemRaw(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Model: "anthropic/claude-haiku-4.5",
		Messages: []types.OpenAIChatMessage{
			{Role: "system", Content: "plain system"},
			{Role: "user", Content: "hi"},
		},
	}
	body, err := ToAnthropic(req, "")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	if body.SystemRaw != nil {
		t.Fatalf("SystemRaw = %v, want nil for a no-breakpoint system", body.SystemRaw)
	}
	if body.System != "plain system" {
		t.Fatalf("System = %q, want \"plain system\"", body.System)
	}
}
