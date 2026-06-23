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
		anthropic:   newAnthropic(boot),
		vertex:      newVertex(boot),
		openai:      newOpenAICompatible("openai", boot.OpenAIAPIKey),
		gemini:      newVertexGemini(boot),
		cerebras:    newOpenAICompatible("cerebras", boot.CerebrasAPIKey),
		deepseek:    newOpenAICompatible("deepseek", boot.DeepSeekAPIKey),
		mistral:     newOpenAICompatible("mistral", boot.MistralAPIKey),
		kimi:        newKimi(boot),
		zai:         newZAI(boot),
		together:    newOpenAICompatible("together", boot.TogetherAPIKey),
		fireworks:   newOpenAICompatible("fireworks", boot.FireworksAPIKey),
		grok:        newOpenAICompatible("grok", boot.GrokAPIKey),
		novita:      newOpenAICompatible("novita", boot.NovitaAPIKey),
		phala:       newOpenAICompatible("phala", boot.PhalaAPIKey),
		siliconflow: newOpenAICompatible("siliconflow", boot.SiliconFlowAPIKey),
		tinfoil:     newTinfoilAttested(boot.TinfoilAPIKey),
		venice:      newOpenAICompatible("venice", boot.VeniceAPIKey),
		parasail:    newOpenAICompatible("parasail", boot.ParasailAPIKey),
		lightning:   newOpenAICompatible("lightning", boot.LightningAPIKey),
		gmi:         newOpenAICompatible("gmi", boot.GMIAPIKey),
		deepinfra:   newOpenAICompatible("deepinfra", boot.DeepInfraAPIKey),
		friendli:    newOpenAICompatible("friendli", boot.FriendliAPIKey),
		nebius:      newOpenAICompatible("nebius", boot.NebiusAPIKey),
		minimax:     newOpenAICompatible("minimax", boot.MiniMaxAPIKey),
		// Xiaomi MiMo — OpenAI-compatible chat completions at api.xiaomimimo.com/v1.
		xiaomi: newOpenAICompatible("xiaomi", boot.XiaomiAPIKey),
		// Cohere — embeddings only (native /v2/embed). Its InvokeStreaming
		// returns an error; embeddings dispatch is in multi_embeddings.go.
		cohere: newCohere(boot.CohereAPIKey),
		// Voyage — embeddings only (OpenAI-shaped /v1/embeddings).
		voyage: newOpenAICompatible("voyage", boot.VoyageAPIKey),
		// Gemini embeddings via the OpenAI-compatible generativelanguage
		// endpoint (directBaseURL("gemini") = .../v1beta/openai). This is
		// SEPARATE from the chat path (m.gemini = Vertex OAuth); embeddings
		// reuse the OpenAI-shaped /embeddings with the QUILL_GEMINI_SECRET key.
		geminiEmbed: newOpenAICompatible("gemini", boot.GeminiAPIKey),
	}
}

type multiClient struct {
	anthropic   *anthropicClient
	vertex      *gcpClient
	openai      *openAICompatibleClient
	gemini      *vertexGeminiClient
	cerebras    *openAICompatibleClient
	deepseek    *openAICompatibleClient
	mistral     *openAICompatibleClient
	kimi        *kimiClient
	zai         *zaiClient
	together    *openAICompatibleClient
	fireworks   *openAICompatibleClient
	grok        *openAICompatibleClient
	novita      *openAICompatibleClient
	phala       *openAICompatibleClient
	siliconflow *openAICompatibleClient
	tinfoil     *openAICompatibleClient
	venice      *openAICompatibleClient
	parasail    *openAICompatibleClient
	lightning   *openAICompatibleClient
	gmi         *openAICompatibleClient
	deepinfra   *openAICompatibleClient
	friendli    *openAICompatibleClient
	nebius      *openAICompatibleClient
	minimax     *openAICompatibleClient
	xiaomi      *openAICompatibleClient
	cohere      *cohereClient
	voyage      *openAICompatibleClient
	geminiEmbed *openAICompatibleClient
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
	case "fireworks":
		return m.fireworks.InvokeStreaming(ctx, req, body, out, options...)
	case "grok":
		return m.grok.InvokeStreaming(ctx, req, body, out, options...)
	case "novita":
		return m.novita.InvokeStreaming(ctx, req, body, out, options...)
	case "phala":
		return m.phala.InvokeStreaming(ctx, req, body, out, options...)
	case "siliconflow":
		return m.siliconflow.InvokeStreaming(ctx, req, body, out, options...)
	case "tinfoil":
		// Tinfoil's TEE attestation verification happens once at boot
		// in newOpenAICompatible(); the verified TLS session pool is
		// reused per-request. See newOpenAICompatible + tinfoil_attest.go
		// for the verifier wiring.
		return m.tinfoil.InvokeStreaming(ctx, req, body, out, options...)
	case "venice":
		return m.venice.InvokeStreaming(ctx, req, body, out, options...)
	case "parasail":
		return m.parasail.InvokeStreaming(ctx, req, body, out, options...)
	case "lightning":
		return m.lightning.InvokeStreaming(ctx, req, body, out, options...)
	case "gmi":
		return m.gmi.InvokeStreaming(ctx, req, body, out, options...)
	case "deepinfra":
		return m.deepinfra.InvokeStreaming(ctx, req, body, out, options...)
	case "friendli":
		return m.friendli.InvokeStreaming(ctx, req, body, out, options...)
	case "nebius":
		return m.nebius.InvokeStreaming(ctx, req, body, out, options...)
	case "minimax":
		return m.minimax.InvokeStreaming(ctx, req, body, out, options...)
	case "xiaomi":
		return m.xiaomi.InvokeStreaming(ctx, req, body, out, options...)
	case "cohere":
		// Embeddings-only; returns a clear "chat not supported" error.
		return m.cohere.InvokeStreaming(ctx, req, body, out, options...)
	default:
		return fmt.Errorf("llm/multi: unsupported provider %q (compiled providers: anthropic, vertex, openai, gemini, cerebras, deepseek, mistral, kimi, zai, together, fireworks, grok, novita, phala, siliconflow, tinfoil, venice, parasail, lightning, gmi, deepinfra, friendli, nebius, minimax, xiaomi, cohere)", provider)
	}
}
