package trustedrouter

import (
	"context"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestConfidentialNeverUsesLocalSpendLeaseAdmission(t *testing.T) {
	ctx := WithConfidentialOnly(context.Background())
	client := &Client{}
	valid := &qtypes.OpenAIChatRequest{Provider: &qtypes.ProviderRouting{MinPrivacy: "confidential"}}
	if plan, err := client.PrepareSpendLeaseAdmission(ctx, "", valid, "chat.completions", time.Now()); plan != nil || err != nil {
		t.Fatalf("plan=%v err=%v", plan, err)
	}
	if _, err := client.PrepareSpendLeaseAdmission(ctx, "", &qtypes.OpenAIChatRequest{}, "chat.completions", time.Now()); err == nil {
		t.Fatal("lost policy not rejected")
	}
}
