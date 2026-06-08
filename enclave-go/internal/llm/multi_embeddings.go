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
	case "voyage":
		return m.voyage.InvokeEmbedding(ctx, req, options...)
	case "deepinfra":
		// Qwen3-Embedding-8B etc. — DeepInfra is OpenAI-shaped at
		// api.deepinfra.com/v1/openai/embeddings; reuses the chat client's key.
		return m.deepinfra.InvokeEmbedding(ctx, req, options...)
	case "gemini":
		// Gemini embeddings via the OpenAI-compatible generativelanguage
		// endpoint (NOT the Vertex chat path). Uses the QUILL_GEMINI_SECRET key.
		return m.geminiEmbed.InvokeEmbedding(ctx, req, options...)
	default:
		return nil, fmt.Errorf("llm/multi: provider %q does not support embeddings", provider)
	}
}
