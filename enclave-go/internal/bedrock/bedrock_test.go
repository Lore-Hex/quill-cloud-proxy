//go:build cloud_aws

package bedrock

import (
	"encoding/json"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestMapModel(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantID string
		wantOk bool
	}{
		{"opus", "claude-opus-4-7", "us.anthropic.claude-opus-4-7", true},
		{"sonnet", "claude-sonnet-4-6", "us.anthropic.claude-sonnet-4-6", true},
		{"haiku", "claude-haiku-4-5-20251001", "us.anthropic.claude-haiku-4-5-20251001-v1:0", true},
		{"unknown", "gpt-4", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, ok := MapModel(tt.input)
			if id != tt.wantID || ok != tt.wantOk {
				t.Errorf("MapModel(%q) = (%q, %v), want (%q, %v)", tt.input, id, ok, tt.wantID, tt.wantOk)
			}
		})
	}
}

func TestSplitCIDPort(t *testing.T) {
	tests := []struct {
		input    string
		wantCID  uint32
		wantPort uint32
	}{
		{"3:8003", 3, 8003},
		{"16:8001", 16, 8001},
		{"invalid", 3, 8003}, // default
		{"", 3, 8003},        // default
	}

	for _, tt := range tests {
		cid := bootstrapCIDFromProxy(tt.input)
		port := bootstrapPortFromProxy(tt.input)
		if cid != tt.wantCID || port != tt.wantPort {
			t.Errorf("split(%q) = (%d, %d), want (%d, %d)", tt.input, cid, port, tt.wantCID, tt.wantPort)
		}
	}
}

func TestBedrockWireProjectionExcludesInternalAndRouterOnlyFields(t *testing.T) {
	body := &qtypes.AnthropicMessagesRequest{
		AnthropicVersion:   "bedrock-2023-05-31",
		System:             "system",
		SystemRaw:          []any{map[string]any{"type": "text", "text": "system"}},
		Messages:           []qtypes.AnthropicMessage{{Role: "user", Content: "private input"}},
		MaxTokens:          128,
		MaxTokensExplicit:  true,
		AnthropicMaxTokens: 256,
		NativeContent:      true,
	}
	encoded, err := json.Marshal(buildAnthropicBedrockWireRequest(body))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, forbidden := range []string{
		"system_raw",
		"native_content",
		"max_tokens_explicit",
		"anthropic_max_tokens",
		"tags",
		"trace",
		"session_id",
		"http_referer",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("Bedrock payload contains %q: %s", forbidden, encoded)
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if payload["max_tokens"] != float64(256) {
		t.Fatalf("max_tokens = %#v, want 256", payload["max_tokens"])
	}
}
