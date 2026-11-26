package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type nativeModelIDVector struct {
	Requested string `json:"requested"`
	Selected  string `json:"selected"`
	Allowed   bool   `json:"allowed"`
}

func loadNativeModelIDVectors(t *testing.T) []nativeModelIDVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/native_model_id_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []nativeModelIDVector `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("no vectors")
	}
	return doc.Cases
}

// With fallbacks disabled, Anthropic's own id is accepted for the catalog
// model it names and for no other model.
func TestValidateAuthorizationRoutingNativeAnthropicIDs(t *testing.T) {
	allow := false
	allowed, refused := 0, 0
	for _, vector := range loadNativeModelIDVectors(t) {
		req := &types.OpenAIChatRequest{
			Model:    vector.Requested,
			Provider: &types.ProviderRouting{AllowFallbacks: &allow},
		}
		authorization := &trustedrouter.Authorization{
			Model: vector.Selected,
			RouteCandidates: []trustedrouter.RouteCandidate{
				{Model: vector.Selected, Provider: "anthropic"},
			},
		}
		err := validateAuthorizationRouting(req, authorization)
		if vector.Allowed {
			allowed++
			if err != nil {
				t.Errorf("%q for %q refused: %v", vector.Requested, vector.Selected, err)
			}
			continue
		}
		refused++
		if err == nil {
			t.Errorf("%q accepted for %q", vector.Requested, vector.Selected)
		}
	}
	if allowed == 0 || refused == 0 {
		t.Fatalf("vectors must hold both outcomes: allowed=%d refused=%d", allowed, refused)
	}
}

// The native rule widens only the model comparison: a second candidate and a
// mismatched candidate model are still refused, and the older spellings keep
// their answers.
func TestNativeAnthropicIDsLeaveTheOtherChecksInPlace(t *testing.T) {
	allow := false
	req := &types.OpenAIChatRequest{
		Model:    "claude-opus-5-5",
		Provider: &types.ProviderRouting{AllowFallbacks: &allow},
	}
	two := &trustedrouter.Authorization{
		Model: "anthropic/claude-opus-5.5",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{Model: "anthropic/claude-opus-5.5", Provider: "anthropic"},
			{Model: "anthropic/claude-opus-5.5", Provider: "amazon-bedrock"},
		},
	}
	if err := validateAuthorizationRouting(req, two); err == nil {
		t.Fatal("two candidates must fail with fallbacks disabled")
	}
	mismatched := &trustedrouter.Authorization{
		Model: "anthropic/claude-opus-5.5",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{Model: "anthropic/claude-sonnet-5.5", Provider: "anthropic"},
		},
	}
	if err := validateAuthorizationRouting(req, mismatched); err == nil {
		t.Fatal("a candidate for another model must fail")
	}
	other := &trustedrouter.Authorization{
		Model: "anthropic/claude-opus-5.5",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{Model: "anthropic/claude-opus-5.5", Provider: "amazon-bedrock"},
		},
	}
	if err := validateAuthorizationRouting(req, other); err != nil {
		t.Fatalf("the named model on another host refused: %v", err)
	}
	for _, pair := range [][2]string{
		{"gpt-4.1", "openai/gpt-4.1"},
		{"gpt-4.1-2025-04-14", "openai/gpt-4.1"},
		{"trustedrouter/auto", "anthropic/claude-opus-5.5"},
		{"anthropic/claude-opus-5.5", "anthropic/claude-opus-5.5"},
	} {
		if !requestedModelAllowsSelection(pair[0], pair[1]) {
			t.Errorf("%q for %q no longer accepted", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{
		{"gpt-4.1", "anthropic/gpt-4.1"},
		{"claude-opus-5-5", "openai/gpt-4.1"},
		{"openai/gpt-4.1", "anthropic/claude-opus-5.5"},
	} {
		if requestedModelAllowsSelection(pair[0], pair[1]) {
			t.Errorf("%q accepted for %q", pair[0], pair[1])
		}
	}
}

func TestStripUndashedModelDate(t *testing.T) {
	for input, want := range map[string]string{
		"claude-haiku-4-5-20251001": "claude-haiku-4-5",
		"claude-haiku-4-5":          "claude-haiku-4-5",
		"claude-haiku-4-5-2025100":  "claude-haiku-4-5-2025100",
		"claude-haiku-4-520251001":  "claude-haiku-4-520251001",
		"-20251001":                 "-20251001",
		"x-20251001":                "x",
		"":                          "",
	} {
		if got := stripUndashedModelDate(input); got != want {
			t.Errorf("stripUndashedModelDate(%q) = %q, want %q", input, got, want)
		}
	}
}
