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
	good := RouteCandidate{Provider: "privatemode", Model: "example", UpstreamModel: "example", UsageType: "Credits"}
	a.RouteCandidates = []RouteCandidate{good}
	if err := validateConfidentialAuthorization(ctx, a); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*RouteCandidate){
		func(c *RouteCandidate) { c.Provider = "other" },
		func(c *RouteCandidate) { c.Model = "" },
		func(c *RouteCandidate) { c.UpstreamModel = "" },
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

func TestReviewedMapleWorkloadIsNotTrusted(t *testing.T) {
	maple := RouteCandidate{Provider: "maple", Model: "dealignai/deepseek-v4.1-flash-1017-uncensored", UpstreamModel: "deepseek-v4-1-flash-1017-uncensored", UsageType: "Credits"}
	for _, a := range []*Authorization{
		{Provider: maple.Provider, Model: maple.Model, UpstreamModel: maple.UpstreamModel, UsageType: maple.UsageType},
		{Provider: "tinfoil", Model: "example", UpstreamModel: "example", RouteCandidates: []RouteCandidate{maple}},
	} {
		if err := validateConfidentialAuthorization(WithTrustedOnly(t.Context()), a); err == nil || err.Type != "trusted_route_unavailable" {
			t.Fatal("Maple must not be a Trusted primary or fallback")
		}
	}
}
