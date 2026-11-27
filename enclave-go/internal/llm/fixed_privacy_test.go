//go:build !llm_multi

package llm

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestFixedBackendRefusesPrivateBeforeCredentialOrNetwork(t *testing.T) {
	c := New(&qtypes.BootstrapData{})
	for _, ctx := range []context.Context{context.Background(), trustedrouter.WithTrustedOnly(context.Background())} {
		req := &qtypes.OpenAIChatRequest{Model: "nyte/confidential"}
		if trustedrouter.TrustedOnly(ctx) {
			req.Model = "ordinary-model"
		}
		err := c.InvokeStreaming(ctx, req, nil, io.Discard, InvokeOptions{Provider: "tinfoil", ProviderAPIKey: "synthetic"})
		if !errors.Is(err, errFixedPrivate) {
			t.Fatalf("fixed provider did not reject private request: %v", err)
		}
	}
}
