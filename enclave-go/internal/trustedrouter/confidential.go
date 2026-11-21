package trustedrouter

import (
	"context"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/maple"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type confidentialOnlyKey struct{}

// WithConfidentialOnly makes the ingress constraint survive internal subcalls.
// Never silently repair a missing filter: that would hide a lost privacy policy.
func WithConfidentialOnly(ctx context.Context) context.Context {
	if TrustedOnly(ctx) {
		return ctx
	}
	return context.WithValue(ctx, confidentialOnlyKey{}, "confidential")
}

func WithTrustedOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, confidentialOnlyKey{}, "trusted")
}

func TrustedOnly(ctx context.Context) bool {
	return ctx.Value(confidentialOnlyKey{}) == "trusted"
}

func ConfidentialOnly(ctx context.Context) bool {
	return TrustedOnly(ctx) || ctx.Value(confidentialOnlyKey{}) == "confidential"
}

func ValidateHostRouting(ctx context.Context, provider *qtypes.ProviderRouting) *ControlPlaneError {
	if TrustedOnly(ctx) {
		if provider == nil || provider.MinPrivacy != "trusted" {
			return &ControlPlaneError{StatusCode: 400, Type: "trusted_privacy_required",
				Message: `This hostname requires provider.min_privacy="trusted". No lower-tier fallback is permitted.`}
		}
		return nil
	}
	return ValidateConfidentialRouting(provider)
}

func ValidateConfidentialRouting(provider *qtypes.ProviderRouting) *ControlPlaneError {
	if provider == nil || provider.MinPrivacy != "confidential" {
		return &ControlPlaneError{
			StatusCode: 400,
			Type:       "confidential_privacy_required",
			Message:    `This hostname requires provider.min_privacy="confidential". No ordinary provider fallback is permitted.`,
		}
	}
	return nil
}

func validateConfidentialAuthorization(ctx context.Context, authorization *Authorization) *ControlPlaneError {
	if authorization != nil && authorization.CustomModel != nil {
		return &ControlPlaneError{StatusCode: 410, Type: "model_not_supported", Message: "Custom models and user-provided models have been retired."}
	}
	if TrustedOnly(ctx) {
		deny := &ControlPlaneError{StatusCode: 503, Type: "trusted_route_unavailable", Message: "No verified Trusted route is available."}
		if authorization == nil || !trustedOperatorRoute(authorization.Provider, authorization.Model, authorization.UpstreamModel, authorization.UsageType) {
			return deny
		}
		for _, candidate := range authorization.RouteCandidates {
			if !trustedOperatorRoute(candidate.Provider, candidate.Model, candidate.UpstreamModel, candidate.UsageType) {
				return deny
			}
		}
		for _, destination := range authorization.BroadcastDestinations {
			if destination.IncludeContent {
				return deny
			}
		}
	}
	return nil
}

// Authorization enforces endpoint E2EE, verified compute and ZDR. Independently
// bound its operator set before a primary or fallback can reach a dispatcher.
func trustedOperatorRoute(provider, model, upstream, usage string) bool {
	switch provider {
	case "tinfoil", "privatemode":
		return model != "" && upstream != ""
	case "maple":
		return model == "dealignai/deepseek-v4.1-flash-1017-uncensored" && upstream == maple.Model && usage == "Credits"
	}
	return false
}
