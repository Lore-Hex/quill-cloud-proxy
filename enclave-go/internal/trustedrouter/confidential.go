package trustedrouter

import (
	"context"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type confidentialOnlyKey struct{}

// WithConfidentialOnly makes the ingress constraint survive internal subcalls.
// Never silently repair a missing filter: that would hide a lost privacy policy.
func WithConfidentialOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, confidentialOnlyKey{}, true)
}

func ConfidentialOnly(ctx context.Context) bool {
	required, _ := ctx.Value(confidentialOnlyKey{}).(bool)
	return required
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
