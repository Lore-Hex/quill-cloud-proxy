//go:build llm_multi

package llm

import (
	"context"
	"testing"
)

func TestRegoloDecisionBYOKWithoutOperatorClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &multiClient{}
	_, err := client.InvokeDecide(ctx, &DecideRequest{Model: "cloudflare/clef-flash"}, InvokeOptions{
		Provider: "regolo", UpstreamModel: "clef-flash", UsageType: "BYOK", ProviderAPIKey: "customer-key",
	})
	if DecideErrorClass(err) != DecideErrCanceled {
		t.Fatalf("BYOK required an operator client: %s", DecideErrorClass(err))
	}
}
