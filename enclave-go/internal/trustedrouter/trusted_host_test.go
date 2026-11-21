package trustedrouter

import (
	"context"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestTrustedHostGuardsPrimaryAndEveryFallback(t *testing.T) {
	ctx := WithConfidentialOnly(WithTrustedOnly(context.Background()))
	if !TrustedOnly(ctx) || !ConfidentialOnly(ctx) || ValidateHostRouting(ctx, nil) == nil || ValidateHostRouting(ctx, &qtypes.ProviderRouting{MinPrivacy: "confidential"}) == nil {
		t.Fatal("lost Trusted floor")
	}
	a := &Authorization{Provider: "tinfoil", Model: "example", UpstreamModel: "example"}
	good := RouteCandidate{Provider: "maple", Model: "dealignai/deepseek-v4.1-flash-1017-uncensored", UpstreamModel: "deepseek-v4-1-flash-1017-uncensored", UsageType: "Credits"}
	a.RouteCandidates = []RouteCandidate{good}
	if err := validateConfidentialAuthorization(ctx, a); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*RouteCandidate){
		func(c *RouteCandidate) { c.Provider = "other" },
		func(c *RouteCandidate) { c.Model = "stock" },
		func(c *RouteCandidate) { c.UpstreamModel = "other" },
		func(c *RouteCandidate) { c.UsageType = "BYOK" },
	} {
		bad := good
		change(&bad)
		a.RouteCandidates = []RouteCandidate{good, bad}
		if err := validateConfidentialAuthorization(ctx, a); err == nil {
			t.Fatal("accepted unqualified fallback")
		}
	}
	a.RouteCandidates = []RouteCandidate{good}
	a.Provider = "unknown"
	if err := validateConfidentialAuthorization(ctx, a); err == nil {
		t.Fatal("accepted unqualified primary")
	}
}
