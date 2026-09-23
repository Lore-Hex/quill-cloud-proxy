//go:build llm_multi

package llm

import (
	"context"
	"fmt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/testutil/fundedrequest"
	"testing"
)

func TestFundedInnerNativeGeminiWire(t *testing.T) {
	for _, total := range []int{1, 800, 1024, 1025, 8192, 32768, 60000} {
		for _, hint := range []any{map[string]any{"max_tokens": 32768}, map[string]any{"budget_tokens": 60000}, map[string]any{"thinking_budget": -1}, map[string]any{"effort": "high"}} {
			for _, model := range []string{"gemini-2.5-pro", "gemini-3.1-pro-preview", "gemini-3.1-flash-image"} {
				t.Run(fmt.Sprintf("%d/%v/%s", total, hint, model), func(t *testing.T) {
					req, body, authorized := fundedrequest.New(t, total, hint, "")
					wire, err := vertexGeminiPayload(context.Background(), req, body, model)
					if err != nil {
						t.Fatal(err)
					}
					fundedrequest.Check(t, wire, authorized, true)
				})
			}
		}
	}
}

func TestFundedInnerGeminiEffortBudget(t *testing.T) {
	for _, total := range []int{1024, 8192, 32768} {
		req, body, authorized := fundedrequest.New(t, total, nil, "high")
		wire, err := vertexGeminiPayload(context.Background(), req, body, "gemini-2.5-pro")
		if err != nil {
			t.Fatal(err)
		}
		fundedrequest.Check(t, wire, authorized, true)
		config := wire["generationConfig"].(map[string]any)["thinkingConfig"].(map[string]any)
		if config["thinkingBudget"] != min(24576, total-1) {
			t.Fatalf("high effort changed: %#v", config)
		}
	}
}

func TestFundedInnerGeminiImageGenerationRetainsLimit(t *testing.T) {
	req, body, authorized := fundedrequest.New(t, 8192, nil, "")
	req.ImageGeneration = true
	wire, err := vertexGeminiPayload(context.Background(), req, body, "gemini-3.1-flash-image")
	if err != nil {
		t.Fatal(err)
	}
	fundedrequest.Check(t, wire, authorized, true)
}
