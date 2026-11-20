package trustedrouter

import (
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// The 2026-11-19 report's repro: one tool whose parameter description is
// 9,000 characters. Before tool definitions were counted the estimate was the
// message alone, len("Say hello in five words.")/4 + 4 = 10 tokens.
func TestEstimateInputTokensCountsToolDefinitions(t *testing.T) {
	message := []qtypes.OpenAIChatMessage{{Role: "user", Content: "Say hello in five words."}}
	withoutTools := EstimateInputTokens(&qtypes.OpenAIChatRequest{Messages: message})
	if withoutTools != 10 {
		t.Fatalf("message-only estimate = %d, want 10", withoutTools)
	}
	tool := map[string]any{
		"type": "function",
		"function": map[string]any{
			"name":        "t0",
			"description": "Tool t0.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"p": map[string]any{"type": "string", "description": strings.Repeat("x", 9_000)},
				},
			},
		},
	}
	withTool := EstimateInputTokens(&qtypes.OpenAIChatRequest{Messages: message, Tools: []any{tool}})
	if withTool < withoutTools+9_000/4 {
		t.Fatalf("estimate with a 9,000-char tool = %d, want at least %d", withTool, withoutTools+9_000/4)
	}
}
