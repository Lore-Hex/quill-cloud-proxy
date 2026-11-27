package trustedrouter

import (
	"context"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type confidentialOnlyKey struct{}
type requestFloorKey struct{}

// WithRequestPrivacy carries the strongest requested floor through subcalls,
// even when a dispatcher constructs a fresh request or chooses a fallback.
func WithRequestPrivacy(ctx context.Context, model string, models []string, provider *qtypes.ProviderRouting) context.Context {
	if TrustedOnly(ctx) {
		return ctx
	}
	floor := ""
	if provider != nil {
		switch strings.ToLower(strings.TrimSpace(provider.MinPrivacy)) {
		case "trusted":
			floor = "trusted"
		case "confidential", "e2e", "e2ee", "max", "maximum":
			floor = "confidential"
		}
	}
	consider := func(id string) {
		base, _, _ := strings.Cut(qtypes.CanonicalRouterModelID(strings.ToLower(strings.TrimSpace(id))), ":")
		switch base {
		case "trustedrouter/trusted":
			floor = "trusted"
		case "trustedrouter/e2e", "trustedrouter/confidential":
			if floor != "trusted" {
				floor = "confidential"
			}
		}
	}
	consider(model)
	for _, id := range models {
		consider(id)
	}
	if floor == "" || ctx.Value(requestFloorKey{}) == floor {
		return ctx
	}
	return context.WithValue(ctx, requestFloorKey{}, floor)
}

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
	return ctx.Value(confidentialOnlyKey{}) == "trusted" || ctx.Value(requestFloorKey{}) == "trusted"
}

func ConfidentialOnly(ctx context.Context) bool {
	return TrustedOnly(ctx) || ctx.Value(confidentialOnlyKey{}) == "confidential" || ctx.Value(requestFloorKey{}) == "confidential"
}

func ValidateHostRouting(ctx context.Context, provider *qtypes.ProviderRouting) *ControlPlaneError {
	if ctx.Value(confidentialOnlyKey{}) == nil {
		return nil
	}
	if ctx.Value(confidentialOnlyKey{}) == "trusted" {
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
	if ConfidentialOnly(ctx) {
		deny := &ControlPlaneError{StatusCode: 503, Type: "confidential_route_unavailable", Message: "No verified Confidential route is available."}
		if TrustedOnly(ctx) {
			deny = &ControlPlaneError{StatusCode: 503, Type: "trusted_route_unavailable", Message: "No verified Trusted route is available."}
		}
		if authorization == nil || !privateRouteAllowed(ctx, authorization.Provider, authorization.Model, authorization.UpstreamModel, authorization.UsageType, authorization.BYOKProvider,
			authorization.BYOKSecretRef != "" || authorization.BYOKEncryptedSecret != nil || authorization.BYOKCacheKey != "") {
			return deny
		}
		for _, candidate := range authorization.RouteCandidates {
			if !privateRouteAllowed(ctx, candidate.Provider, candidate.Model, candidate.UpstreamModel, candidate.UsageType, candidate.BYOKProvider,
				candidate.BYOKSecretRef != "" || candidate.BYOKEncryptedSecret != nil || candidate.BYOKCacheKey != "") {
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

func privateRouteAllowed(ctx context.Context, provider, model, upstream, usage, keyProvider string, hasSecret bool) bool {
	if TrustedOnly(ctx) && provider != "tinfoil" && provider != "privatemode" {
		return false
	}
	byok, ok := confidentialRoutes[[3]string{provider, model, upstream}]
	if !ok {
		return false
	}
	return (usage == "Credits" && !hasSecret && keyProvider == "") ||
		(usage == "BYOK" && byok && keyProvider == provider && hasSecret)
}

// PrivateDispatchAllowed checks the actual adapter arguments, including a
// resolved BYOK credential, again on every dispatch attempt.
func PrivateDispatchAllowed(ctx context.Context, provider, model, upstream, usage string, hasKey bool) bool {
	if !ConfidentialOnly(ctx) {
		return true
	}
	keyProvider := ""
	if hasKey {
		keyProvider = provider
	}
	return privateRouteAllowed(ctx, provider, model, upstream, usage, keyProvider, hasKey)
}
