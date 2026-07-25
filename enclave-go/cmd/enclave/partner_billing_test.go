package main

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestApplyPartnerSettlementDetailsPublishesExactPricingContract(t *testing.T) {
	details := map[string]any{}
	applyPartnerSettlementDetails(
		details,
		&trustedrouter.SettleResult{CostMicrodollars: 1_000},
	)

	if got := details["cost_microdollars"]; got != 1_000 {
		t.Fatalf("cost_microdollars = %v, want 1000", got)
	}
	if got := details["billing_provider"]; got != "parasail" {
		t.Fatalf("billing_provider = %v, want parasail", got)
	}
	pricing, ok := details["pricing"].(map[string]any)
	if !ok {
		t.Fatalf("pricing = %T, want map[string]any", details["pricing"])
	}
	if got := pricing["input_microdollars_per_million_tokens"]; got != 2_000_000 {
		t.Fatalf("input price = %v, want 2000000", got)
	}
	if got := pricing["output_microdollars_per_million_tokens"]; got != 19_000_000 {
		t.Fatalf("output price = %v, want 19000000", got)
	}
	if got := pricing["minimum_charge_microdollars"]; got != 1_000 {
		t.Fatalf("minimum charge = %v, want 1000", got)
	}
}
