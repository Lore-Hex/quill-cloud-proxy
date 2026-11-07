package main

import (
	"context"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

// Shaped like GET /v1/models: gpt-5.5 tops out at xhigh, GLM skips medium,
// Gemma takes no effort, Mystery declares nothing either way, Auto-only
// declares nothing we can rank, and Garbled is malformed. Garbled must not
// stop the other rows from being read.
const effortTestCatalog = `{"data":[
 {"id":"openai/gpt-5.5","trustedrouter":{"supports_chat":true,"prepaid_available":true,"capabilities":{"reasoning_effort":["none","low","medium","high","xhigh"]}}},
 {"id":"z-ai/glm-5.3","trustedrouter":{"supports_chat":true,"prepaid_available":true,"capabilities":{"reasoning_effort":["low","high","max"]}}},
 {"id":"google/gemma-4-31b-it","trustedrouter":{"supports_chat":true,"prepaid_available":true,"capabilities":{"reasoning_effort":[]}}},
 {"id":"acme/mystery","trustedrouter":{"supports_chat":true,"prepaid_available":true,"capabilities":{"reasoning_effort":null}}},
 {"id":"acme/auto-only","trustedrouter":{"supports_chat":true,"prepaid_available":true,"capabilities":{"reasoning_effort":["auto"]}}},
 {"id":"acme/garbled","trustedrouter":{"supports_chat":true,"prepaid_available":true,"capabilities":{"reasoning_effort":"auto"}}}
]}`

func TestPolyphemusClampsTheRecommendedEffortToTheModelsOwn(t *testing.T) {
	tests := []struct{ model, recommended, want string }{
		{"openai/gpt-5.5", "max", "xhigh"},    // the DRACO failure: above the model's top
		{"openai/gpt-5.5", "high", "high"},    // supported as is
		{"openai/gpt-5.5", "MAX", "xhigh"},    // case-insensitive
		{"z-ai/glm-5.3", "medium", "low"},     // strongest supported at or below
		{"z-ai/glm-5.3", "minimal", "low"},    // nothing below: weakest above
		{"google/gemma-4-31b-it", "high", ""}, // declares no efforts: send none
		{"google/gemma-4-31b-it", "auto", ""}, // ...even for an effort we cannot rank
		{"acme/auto-only", "max", "max"},      // nothing rankable declared: pass through
		{"acme/garbled", "max", "max"},        // malformed declaration: pass through
		{"acme/mystery", "max", "max"},        // unknown declaration: pass through
		{"acme/not-in-catalog", "max", "max"}, // no row: pass through
		{"openai/gpt-5.5", "turbo", "turbo"},  // unrankable: pass through
		{"openai/gpt-5.5", "", ""},            // no recommendation
	}
	for _, tt := range tests {
		if got := polyphemusSupportedEffort([]byte(effortTestCatalog), tt.model, tt.recommended); got != tt.want {
			t.Errorf("%s %q -> %q, want %q", tt.model, tt.recommended, got, tt.want)
		}
	}
	if got := polyphemusSupportedEffort([]byte("not json"), "openai/gpt-5.5", "max"); got != "max" {
		t.Errorf("unreadable catalog -> %q, want the recommendation", got)
	}
}

func TestPolyphemusSendsTheChosenModelAnEffortItAccepts(t *testing.T) {
	selector := selectionStub(func(context.Context, string, llm.SelectionControls, string) (*llm.ModelSelection, error) {
		out := &llm.ModelSelection{Model: "openai/gpt-5.5"}
		out.Reasoning.Effort = "max"
		return out, nil
	})
	req := selectionTestRequest()
	if _, err := preparePolyphemus(context.Background(), req, &selectionGatewayStub{catalog: effortTestCatalog}, selector, "private-key", "log-1"); err != nil {
		t.Fatal(err)
	}
	if req.Model != "openai/gpt-5.5" || req.ReasoningEffort != "xhigh" {
		t.Fatalf("model=%q effort=%q, want openai/gpt-5.5 at xhigh", req.Model, req.ReasoningEffort)
	}

	// A caller's own effort is never rewritten.
	req = selectionTestRequest()
	req.ReasoningEffort = "max"
	if _, err := preparePolyphemus(context.Background(), req, &selectionGatewayStub{catalog: effortTestCatalog}, selector, "private-key", "log-2"); err != nil {
		t.Fatal(err)
	}
	if req.ReasoningEffort != "max" {
		t.Fatalf("caller effort rewritten to %q", req.ReasoningEffort)
	}
}
