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
	a := &Authorization{Provider: "tinfoil", Model: "openai/gpt-oss-120b", UpstreamModel: "gpt-oss-120b", UsageType: "Credits"}
	good := RouteCandidate{Provider: "privatemode", Model: "z-ai/glm-5.3", UpstreamModel: "glm-5.3", UsageType: "Credits"}
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
		{Provider: "tinfoil", Model: "openai/gpt-oss-120b", UpstreamModel: "gpt-oss-120b", UsageType: "Credits", RouteCandidates: []RouteCandidate{maple}},
	} {
		if err := validateConfidentialAuthorization(WithTrustedOnly(t.Context()), a); err == nil || err.Type != "trusted_route_unavailable" {
			t.Fatal("Maple must not be a Trusted primary or fallback")
		}
	}
}

func TestRequestPrivacyAppliesToEveryCandidateAndInheritedCalls(t *testing.T) {
	maple := RouteCandidate{Provider: "maple", Model: "dealignai/deepseek-v4.1-flash-1017-uncensored", UpstreamModel: "deepseek-v4-1-flash-1017-uncensored", UsageType: "Credits"}
	for _, ctx := range []context.Context{
		WithConfidentialOnly(t.Context()),
		WithRequestPrivacy(t.Context(), "nyte/e2e", nil, nil),
		WithRequestPrivacy(t.Context(), "other", []string{"nyte/confidential"}, nil),
		WithRequestPrivacy(t.Context(), "other", nil, &qtypes.ProviderRouting{MinPrivacy: "maximum"}),
	} {
		a := &Authorization{Provider: maple.Provider, Model: maple.Model, UpstreamModel: maple.UpstreamModel, UsageType: "Credits"}
		child := WithRequestPrivacy(ctx, "other", nil, nil)
		if err := validateConfidentialAuthorization(child, a); err != nil {
			t.Fatal(err)
		}
		for _, modify := range []func(*RouteCandidate){
			func(c *RouteCandidate) { c.Provider = "other" },
			func(c *RouteCandidate) { c.Model = "other" },
			func(c *RouteCandidate) { c.UpstreamModel = "other" },
			func(c *RouteCandidate) { c.UsageType = "BYOK" },
			func(c *RouteCandidate) { c.BYOKSecretRef = "unexpected" },
		} {
			bad := maple
			modify(&bad)
			a.RouteCandidates = []RouteCandidate{maple, bad}
			if validateConfidentialAuthorization(child, a) == nil {
				t.Fatal("accepted unreviewed candidate")
			}
			if err := validateConfidentialAuthorization(t.Context(), a); err != nil {
				t.Fatal("ordinary routing changed", err)
			}
		}
		a.RouteCandidates = nil
		a.BroadcastDestinations = []BroadcastDestination{{IncludeContent: true}}
		if validateConfidentialAuthorization(child, a) == nil {
			t.Fatal("authorized content export")
		}
	}
	if !TrustedOnly(WithRequestPrivacy(WithConfidentialOnly(t.Context()), "other", []string{"nyte/trusted:online"}, nil)) {
		t.Fatal("fallback alias failed to raise the outer request floor")
	}
}
