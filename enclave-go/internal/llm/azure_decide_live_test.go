//go:build llm_multi

package llm

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

func TestAzureDecisionLive(t *testing.T) {
	if os.Getenv("TR_RUN_AZURE_DECISION_LIVE") != "1" {
		t.Skip("opt-in paid Azure decision smoke")
	}
	key := os.Getenv("AZURE_API_KEY")
	if key == "" {
		t.Fatal("AZURE_API_KEY is required")
	}
	req, specs := hostedRequest(t)
	req.Model = "microsoft/microsoft-decision-1"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := &multiClient{azure: newAzure(key)}
	response, err := client.InvokeDecide(ctx, req, InvokeOptions{Provider: "azure", UpstreamModel: "tr-decision-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decide.Verify(specs, response.Answers); err != nil {
		t.Fatalf("response failed verification: %v", err)
	}
	if response.InputTokens <= 0 || response.OutputTokens < 0 {
		t.Fatal("missing usage")
	}
	t.Logf("verified all three answer types; input_tokens=%d output_tokens=%d", response.InputTokens, response.OutputTokens)
}
