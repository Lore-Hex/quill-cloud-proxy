//go:build llm_multi

package llm

import (
	"context"
	"fmt"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// InvokeEmbedding implements EmbeddingClient for the multi-provider gateway.
// It dispatches to the per-provider embeddings client by the provider slug
// the control plane assigned in the authorization. Only the embedding-capable
// providers are wired (openai, together, cohere); gemini is deferred (Vertex
// :predict wiring), and everything else returns a clear error.
func (m *multiClient) InvokeEmbedding(
	ctx context.Context,
	req *qtypes.EmbeddingRequest,
	options ...InvokeOptions,
) (*qtypes.EmbeddingResponse, error) {
	provider := normalizeDirectProvider(firstOptions(options).Provider)
	switch provider {
	case "openai":
		return m.openai.InvokeEmbedding(ctx, req, options...)
	case "together":
		return m.together.InvokeEmbedding(ctx, req, options...)
	case "cohere":
		return m.cohere.InvokeEmbedding(ctx, req, options...)
	case "gemini":
		// DEFERRED: the enclave's Gemini path runs through Vertex AI (OAuth),
		// whose embeddings use the Vertex `:predict` endpoint rather than the
		// OpenAI-shaped `/embeddings`. gemini-embedding-001 stays in the
		// catalog; this returns a clean error until the Vertex wiring lands.
		return nil, fmt.Errorf("llm/multi: gemini embeddings not yet supported")
	default:
		return nil, fmt.Errorf("llm/multi: provider %q does not support embeddings", provider)
	}
}
