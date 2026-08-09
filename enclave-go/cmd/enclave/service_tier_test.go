package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// Settlement happens AFTER the upstream generation has been made and paid for,
// so a tier word the control plane refuses costs us the provider spend AND
// fails the caller's request. Anthropic reports "standard" where OpenAI reports
// "default"; forwarding that verbatim 502'd every anthropic/* request in
// production with "settlement service_tier must be the actual default or
// priority tier".
func TestCanonicalServiceTier(t *testing.T) {
	cases := []struct {
		reported string
		want     string
		ok       bool
	}{
		{"standard", "default", true},     // Anthropic's word for the ordinary tier
		{"STANDARD", "default", true},     // providers are inconsistent about case
		{"  standard  ", "default", true}, // ...and about whitespace
		{"default", "default", true},      // OpenAI's word
		{"priority", "priority", true},
		// Cheaper tiers must NOT become "default": settling one of those at the
		// default rate would overcharge the customer.
		{"batch", "", false},
		{"flex", "", false},
		{"scale", "", false},
		// Unknown or absent: drop it, keeping the requested tier that was
		// already validated before the request went upstream.
		{"turbo-supreme", "", false},
		{"", "", false},
	}

	for _, tc := range cases {
		got, ok := canonicalServiceTier(tc.reported)
		if got != tc.want || ok != tc.ok {
			t.Errorf("canonicalServiceTier(%q) = (%q, %v), want (%q, %v)",
				tc.reported, got, ok, tc.want, tc.ok)
		}
	}
}

func TestApplyCacheUsageNormalizesAnthropicStandard(t *testing.T) {
	usage := trustedrouter.Usage{ServiceTier: "default"}
	applyCacheUsage(&usage, adapter.StreamResult{
		Usage: &adapter.StreamUsage{ServiceTier: "standard"},
	})
	if usage.ServiceTier != "default" {
		t.Errorf("anthropic %q settled as %q, want default", "standard", usage.ServiceTier)
	}
}

// An unusable provider report must leave the requested tier untouched rather
// than overwriting it with a word settlement will reject.
func TestApplyCacheUsageKeepsRequestedTierWhenReportIsUnusable(t *testing.T) {
	for _, reported := range []string{"", "batch", "nonsense"} {
		usage := trustedrouter.Usage{ServiceTier: "priority"}
		applyCacheUsage(&usage, adapter.StreamResult{
			Usage: &adapter.StreamUsage{ServiceTier: reported},
		})
		if usage.ServiceTier != "priority" {
			t.Errorf("reported %q overwrote the requested tier with %q", reported, usage.ServiceTier)
		}
	}
}
