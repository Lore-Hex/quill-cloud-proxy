package llm

import (
	"context"
	"errors"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var errFixedPrivate = errors.New("private inference unavailable on this fixed provider")

// A fixed adapter cannot honor a different provider named by authorization.
func rejectFixedProviderPrivate(ctx context.Context, req *qtypes.OpenAIChatRequest) error {
	if req != nil {
		ctx = trustedrouter.WithRequestPrivacy(ctx, req.Model, req.Models, req.Provider)
	}
	if trustedrouter.ConfidentialOnly(ctx) {
		return errFixedPrivate
	}
	return nil
}
