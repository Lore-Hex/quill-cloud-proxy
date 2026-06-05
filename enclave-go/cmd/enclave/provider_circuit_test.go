package main

import (
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

func TestProviderCircuitOpensAndThenHalfOpens(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	registry := &providerCircuitRegistry{
		enabled:   true,
		threshold: 2,
		openFor:   time.Minute,
		now:       func() time.Time { return now },
		states:    map[string]providerCircuitState{},
	}
	option := llm.InvokeOptions{
		Provider:   "anthropic",
		Model:      "anthropic/claude-haiku-4.5",
		EndpointID: "anthropic/claude-haiku-4.5@anthropic/prepaid",
	}

	if !registry.Allow(option) {
		t.Fatal("fresh circuit should allow")
	}
	if opened := registry.RecordFailure(option); opened {
		t.Fatal("first failure should not open circuit")
	}
	if !registry.Allow(option) {
		t.Fatal("circuit should stay closed before threshold")
	}
	if opened := registry.RecordFailure(option); !opened {
		t.Fatal("second failure should open circuit")
	}
	if registry.Allow(option) {
		t.Fatal("open circuit should reject while TTL has not elapsed")
	}

	now = now.Add(61 * time.Second)
	if !registry.Allow(option) {
		t.Fatal("expired circuit should half-open")
	}
	registry.RecordSuccess(option)
	if !registry.Allow(option) {
		t.Fatal("success should close the circuit")
	}
}

func TestProviderCircuitKeyIncludesProviderRegionAndFamily(t *testing.T) {
	t.Setenv("TR_REGION", "europe-west4")
	key := providerCircuitKey(llm.InvokeOptions{
		Provider:   "openai",
		Model:      "openai/gpt-4.1-mini:free",
		EndpointID: "openai/gpt-4.1-mini@openai/byok",
	})

	want := "openai|europe-west4|openai/gpt"
	if key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
}

func TestParseFirstByteBudgetDefaultsToProductionBudget(t *testing.T) {
	for _, raw := range []string{"", "0", "-1", "not-a-number"} {
		if got := parseFirstByteBudget(raw); got != 20*time.Second {
			t.Errorf("parseFirstByteBudget(%q) = %s, want 20s", raw, got)
		}
	}
	if got := parseFirstByteBudget("35"); got != 35*time.Second {
		t.Fatalf("parseFirstByteBudget(valid) = %s, want 35s", got)
	}
}
