package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
)

func TestNeurometricDecisionUsagePreservesAuthoritativeZero(t *testing.T) {
	for _, tc := range []struct {
		name          string
		model         string
		usage         *adapter.StreamUsage
		input, output int
		estimated     bool
	}{
		{"decision", "neurometric/structured-decisions", &adapter.StreamUsage{InputTokens: 167}, 167, 0, false},
		{"generated", "neurometric/structured-decisions", &adapter.StreamUsage{InputTokens: 167, OutputTokens: 6}, 167, 6, false},
		{"missing", "neurometric/structured-decisions", nil, 42, 9, true},
		{"empty", "neurometric/structured-decisions", &adapter.StreamUsage{}, 42, 9, true},
		{"negative", "neurometric/structured-decisions", &adapter.StreamUsage{InputTokens: 167, OutputTokens: -1}, 42, 9, true},
		{"other-task", "neurometric/conversation-summary", &adapter.StreamUsage{InputTokens: 167}, 42, 9, true},
		{"custom-alias", "trustedrouter/user-example", &adapter.StreamUsage{InputTokens: 167}, 42, 9, true},
		{"similar-name", "neurometric/structured-decisions-other", &adapter.StreamUsage{InputTokens: 167}, 42, 9, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out, estimated := realOrEstimatedTokens(adapter.StreamResult{Usage: tc.usage}, 42, 9, tc.model)
			if in != tc.input || out != tc.output || estimated != tc.estimated {
				t.Fatalf("got (%d, %d, %t), want (%d, %d, %t)", in, out, estimated, tc.input, tc.output, tc.estimated)
			}
		})
	}
}
