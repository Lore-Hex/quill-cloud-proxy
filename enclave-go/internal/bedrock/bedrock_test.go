//go:build cloud_aws

package bedrock

import (
	"testing"
)

func TestMapModel(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantID  string
		wantOk  bool
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
