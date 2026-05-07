//go:build llm_multi

// Multi-provider gateway. Compiled with `-tags 'cloud_gcp,llm_multi'` so
// the binary contains both the Anthropic-direct client and the Vertex-direct
// client. At request time, the dispatcher picks one based on the provider
// the trustedrouter control plane assigned to the request (carried in the
// authorization → InvokeOptions.Provider field).
//
// Adding a new provider here is two lines:
//  1. add a *yourClient to multiClient
//  2. add a case in the switch on opts.Provider
//
// The build tag system keeps single-backend builds (llm_anthropic,
// llm_vertex) untouched — those keep their smaller binaries and tighter
// audit surfaces. Multi exists for product flexibility ("user can pick
// the upstream provider") at the cost of a larger PCR0/image_digest
// surface.
package llm

import (
	"context"
	"fmt"
	"io"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// New returns the multi-provider dispatcher. Each backend is constructed
// up-front so connection pools and any cached state warm up at boot.
func New(boot *qtypes.BootstrapData) Client {
	return &multiClient{
		anthropic: newAnthropic(boot),
		vertex:    newVertex(boot),
		openai:    newOpenAICompatible("openai", boot.OpenAIAPIKey),
		gemini:    newVertexGemini(boot),
		cerebras:  newOpenAICompatible("cerebras", boot.CerebrasAPIKey),
		deepseek:  newOpenAICompatible("deepseek", boot.DeepSeekAPIKey),
		mistral:   newOpenAICompatible("mistral", boot.MistralAPIKey),
		kimi:      newKimi(boot),
		zai:       newZAI(boot),
		together:  newOpenAICompatible("together", boot.TogetherAPIKey),
	}
}

type multiClient struct {
	anthropic *anthropicClient
	vertex    *gcpClient
	openai    *openAICompatibleClient
	gemini    *vertexGeminiClient
	cerebras  *openAICompatibleClient
	deepseek  *openAICompatibleClient
	mistral   *openAICompatibleClient
	kimi      *kimiClient
	zai       *zaiClient
	together  *openAICompatibleClient
}

func (m *multiClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if handled, err := invokeBYOKStreaming(ctx, req, body, out, firstOptions(options)); handled {
		return err
	}
	provider := normalizeDirectProvider(firstOptions(options).Provider)
	switch provider {
	case "anthropic", "":
		// Empty provider falls through to anthropic for backward compatibility
		// — earlier deploys didn't always populate options.Provider, and the
		// anthropic-direct path is the safest default for Claude requests.
		return m.anthropic.InvokeStreaming(ctx, req, body, out, options...)
	case "vertex", "google", "google-vertex":
		return m.vertex.InvokeStreaming(ctx, req, body, out, options...)
	case "openai":
		return m.openai.InvokeStreaming(ctx, req, body, out, options...)
	case "gemini":
		return m.gemini.InvokeStreaming(ctx, req, body, out, options...)
	case "cerebras":
		return m.cerebras.InvokeStreaming(ctx, req, body, out, options...)
	case "deepseek":
		return m.deepseek.InvokeStreaming(ctx, req, body, out, options...)
	case "mistral":
		return m.mistral.InvokeStreaming(ctx, req, body, out, options...)
	case "kimi":
		return m.kimi.InvokeStreaming(ctx, req, body, out, options...)
	case "zai":
		return m.zai.InvokeStreaming(ctx, req, body, out, options...)
	case "together":
		return m.together.InvokeStreaming(ctx, req, body, out, options...)
	default:
		return fmt.Errorf("llm/multi: unsupported provider %q (compiled providers: anthropic, vertex, openai, gemini, cerebras, deepseek, mistral, kimi, zai, together)", provider)
	}
}
