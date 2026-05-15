package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func firstOptions(options []InvokeOptions) InvokeOptions {
	if len(options) == 0 {
		return InvokeOptions{}
	}
	return options[0]
}

func invokeBYOKStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options InvokeOptions,
) (bool, error) {
	if strings.TrimSpace(options.ProviderAPIKey) == "" {
		return false, nil
	}
	provider := normalizeDirectProvider(options.Provider)
	switch {
	case provider == "anthropic":
		return true, invokeAnthropicBYOKStreaming(ctx, req, body, out, options.ProviderAPIKey, options.UpstreamModel)
	case isOpenAICompatibleBYOKProvider(provider):
		return true, invokeOpenAICompatibleBYOKStreaming(ctx, provider, req, body, out, options.ProviderAPIKey, options.UpstreamModel)
	default:
		return true, fmt.Errorf("llm/byok: unsupported provider %q", options.Provider)
	}
}

func isOpenAICompatibleBYOKProvider(provider string) bool {
	switch provider {
	case "openai", "cerebras", "deepseek", "mistral", "kimi", "gemini", "zai", "together",
		"grok", "novita", "phala", "siliconflow", "tinfoil", "venice",
		"parasail", "lightning", "gmi", "deepinfra", "nebius", "minimax":
		return true
	default:
		return false
	}
}

type openAICompatibleRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
	// max_tokens vs max_completion_tokens: OpenAI's gpt-5.x family
	// (gpt-5, gpt-5.1, ..., gpt-5.4, gpt-5.4-mini, gpt-5.4-nano,
	// gpt-5.5, ...) REQUIRES `max_completion_tokens` and returns
	// 400 `unsupported_parameter: max_tokens` if you send the older
	// name. Pre-5.x models still accept `max_tokens`. Some other
	// openai-compatible providers (zai, kimi, novita, etc.) only
	// know `max_tokens`. So this client emits ONE or the OTHER per
	// request — see buildOpenAICompatibleRequest below.
	MaxTokens           int      `json:"max_tokens,omitempty"`
	MaxCompletionTokens int      `json:"max_completion_tokens,omitempty"`
	Temperature         *float64 `json:"temperature,omitempty"`
	TopP                *float64 `json:"top_p,omitempty"`
	ResponseFormat      any      `json:"response_format,omitempty"`
	Tools               []any    `json:"tools,omitempty"`
	ToolChoice          any      `json:"tool_choice,omitempty"`
	ParallelToolCalls   *bool    `json:"parallel_tool_calls,omitempty"`
	Thinking            any      `json:"thinking,omitempty"`
}

// requiresMaxCompletionTokens returns true for OpenAI models that
// reject the legacy `max_tokens` parameter. Currently the gpt-5.x
// family (and the o-series via the same Responses-style param naming
// — though we mostly route those through the Responses API). Match
// is intentionally loose: any model id that starts with `gpt-5`,
// `o1`, `o3`, or `o4` (with optional vendor prefix) flips the
// parameter name. Add more as OpenAI ships new families.
func requiresMaxCompletionTokens(provider, modelID string) bool {
	if provider != "openai" {
		return false
	}
	m := strings.ToLower(modelID)
	// Strip vendor prefix if present (e.g. "openai/gpt-5.4-mini" -> "gpt-5.4-mini").
	if i := strings.Index(m, "/"); i >= 0 {
		m = m[i+1:]
	}
	for _, prefix := range []string{"gpt-5", "o1", "o3", "o4"} {
		if strings.HasPrefix(m, prefix) {
			return true
		}
	}
	return false
}

type chatMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

func invokeOpenAICompatibleBYOKStreaming(
	ctx context.Context,
	provider string,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	apiKey string,
	upstreamModel string,
) error {
	return InvokeOpenAICompatibleStreaming(ctx, provider, directBaseURL(provider), apiKey, req, body, out, upstreamModel)
}

// InvokeOpenAICompatibleStreaming is the shared OpenAI-compatible upstream
// streaming helper used by both the BYOK path (per-user API key) and the
// credit-flow path (Quill-managed API key fetched from Secret Manager).
// Reads upstream OpenAI ChatCompletion SSE chunks, translates to native
// Anthropic SSE so the rest of the gateway pipeline keeps its current
// Anthropic-shaped contract.
//
// Provider must be the normalized slug ("kimi", "zai", "openai", etc.).
// baseURL should not have a trailing slash; "/chat/completions" is
// appended. apiKey is sent as a Bearer token.
func InvokeOpenAICompatibleStreaming(
	ctx context.Context,
	provider, baseURL, apiKey string,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	upstreamModel string,
) error {
	return invokeOpenAICompatibleStreamingWithClient(
		ctx,
		defaultHTTPClient(),
		provider,
		baseURL,
		apiKey,
		req,
		body,
		out,
		upstreamModel,
	)
}

func invokeOpenAICompatibleStreamingWithClient(
	ctx context.Context,
	httpc *http.Client,
	provider, baseURL, apiKey string,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	upstreamModel string,
) error {
	if strings.TrimSpace(apiKey) == "" {
		return fmt.Errorf("llm/%s: missing api key", provider)
	}
	if strings.TrimSpace(baseURL) == "" {
		return fmt.Errorf("llm/%s: missing base URL", provider)
	}
	msgs, err := openAICompatibleMessagesWithFetchedImages(ctx, body)
	if err != nil {
		return err
	}
	upstreamID := directModelID(provider, req.Model, upstreamModel)
	reqBody := openAICompatibleRequest{
		Model:             upstreamID,
		Messages:          msgs,
		Stream:            true,
		Temperature:       body.Temperature,
		TopP:              body.TopP,
		ResponseFormat:    req.ResponseFormat,
		Tools:             req.Tools,
		ToolChoice:        req.ToolChoice,
		ParallelToolCalls: req.ParallelTools,
	}
	if kimiToolsNeedThinkingDisabled(provider, upstreamID, req.Tools) {
		reqBody.Thinking = map[string]string{"type": "disabled"}
	}
	// Per-model parameter rename: openai gpt-5.x rejects max_tokens
	// and requires max_completion_tokens. Every other openai-compatible
	// provider (and pre-5.x openai models) still wants max_tokens.
	// Emit exactly one of the two so the upstream parser doesn't
	// complain about the absent-but-listed-in-struct field (omitempty
	// hides ints == 0).
	if requiresMaxCompletionTokens(provider, upstreamID) {
		reqBody.MaxCompletionTokens = body.MaxTokens
	} else {
		reqBody.MaxTokens = body.MaxTokens
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("llm/%s: marshal body: %w", provider, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("User-Agent", "TrustedRouter/1.0")

	if httpc == nil {
		httpc = defaultHTTPClient()
	}
	resp, err := httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/%s: invoke: %w", provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("llm/%s: read error body: %w", provider, readErr)
		}
		return &upstreamHTTPError{status: resp.StatusCode, body: string(errBody)}
	}
	return translateOpenAIStreamToAnthropic(resp.Body, out)
}

func kimiToolsNeedThinkingDisabled(provider, modelID string, tools []any) bool {
	if provider != "kimi" || len(tools) == 0 {
		return false
	}
	model := strings.ToLower(modelID)
	return strings.Contains(model, "k2.6") || strings.Contains(model, "k2.5")
}

func invokeAnthropicBYOKStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	apiKey string,
	upstreamModel string,
) error {
	messages, err := anthropicMessagesWithFetchedImages(ctx, body)
	if err != nil {
		return err
	}
	reqBody := struct {
		Model       string                      `json:"model"`
		Messages    []qtypes.AnthropicMessage   `json:"messages"`
		System      string                      `json:"system,omitempty"`
		MaxTokens   int                         `json:"max_tokens"`
		Temperature *float64                    `json:"temperature,omitempty"`
		TopP        *float64                    `json:"top_p,omitempty"`
		Tools       []qtypes.AnthropicTool      `json:"tools,omitempty"`
		ToolChoice  *qtypes.AnthropicToolChoice `json:"tool_choice,omitempty"`
		Stream      bool                        `json:"stream"`
	}{
		Model:       directModelID("anthropic", req.Model, upstreamModel),
		Messages:    messages,
		System:      body.System,
		MaxTokens:   body.MaxTokens,
		Temperature: body.Temperature,
		TopP:        body.TopP,
		Tools:       body.Tools,
		ToolChoice:  body.ToolChoice,
		Stream:      true,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("llm/byok: marshal anthropic body: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := defaultHTTPClient().Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/byok: anthropic invoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("llm/byok: read anthropic error body: %w", readErr)
		}
		return &upstreamHTTPError{status: resp.StatusCode, body: string(errBody)}
	}
	_, err = io.Copy(out, resp.Body)
	return err
}

func openAICompatibleMessagesWithFetchedImages(
	ctx context.Context,
	body *qtypes.AnthropicMessagesRequest,
) ([]chatMessage, error) {
	msgs := make([]chatMessage, 0, len(body.Messages)+1)
	if body.System != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: body.System})
	}
	for _, message := range body.Messages {
		content, err := openAICompatibleContentWithFetchedImages(ctx, message.Content)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, chatMessage{Role: message.Role, Content: content})
	}
	return msgs, nil
}

func openAICompatibleContentWithFetchedImages(ctx context.Context, content any) (any, error) {
	switch value := content.(type) {
	case string:
		return value, nil
	case []qtypes.ChatContentPart:
		return openAICompatiblePartsWithFetchedImages(ctx, value)
	case []any:
		parts := make([]qtypes.ChatContentPart, 0, len(value))
		for _, item := range value {
			part, err := chatPartFromAny(item)
			if err != nil {
				return nil, err
			}
			parts = append(parts, part)
		}
		return openAICompatiblePartsWithFetchedImages(ctx, parts)
	default:
		return content, nil
	}
}

func openAICompatiblePartsWithFetchedImages(
	ctx context.Context,
	parts []qtypes.ChatContentPart,
) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(parts))
	for _, part := range parts {
		switch part.Type {
		case "", "text", "input_text":
			if strings.TrimSpace(part.Text) != "" {
				out = append(out, map[string]any{"type": "text", "text": part.Text})
			}
		case "image_url", "input_image":
			if part.ImageURL == nil || strings.TrimSpace(part.ImageURL.URL) == "" {
				return nil, fmt.Errorf("llm/image: image_url is required")
			}
			dataURL, err := openAICompatibleImageDataURL(ctx, part.ImageURL.URL)
			if err != nil {
				return nil, err
			}
			imageURL := map[string]any{"url": dataURL}
			if strings.TrimSpace(part.ImageURL.Detail) != "" {
				imageURL["detail"] = part.ImageURL.Detail
			}
			out = append(out, map[string]any{
				"type":      "image_url",
				"image_url": imageURL,
			})
		default:
			return nil, fmt.Errorf("llm/image: unsupported content part %q", part.Type)
		}
	}
	return out, nil
}

func openAICompatibleImageDataURL(ctx context.Context, raw string) (string, error) {
	mediaType, data, err := loadImageBytes(ctx, raw)
	if err != nil {
		return "", err
	}
	normalizedType, normalizedData, err := normalizeImageBytes(mediaType, data)
	if err != nil {
		return "", err
	}
	return "data:" + normalizedType + ";base64," + base64.StdEncoding.EncodeToString(normalizedData), nil
}

func directBaseURL(provider string) string {
	switch provider {
	case "openai":
		return "https://api.openai.com/v1"
	case "cerebras":
		return "https://api.cerebras.ai/v1"
	case "deepseek":
		return "https://api.deepseek.com"
	case "mistral":
		return "https://api.mistral.ai/v1"
	case "kimi":
		return "https://api.moonshot.ai/v1"
	case "gemini":
		return "https://generativelanguage.googleapis.com/v1beta/openai"
	case "zai":
		// Z.AI's open OpenAI-compatible endpoint. The legacy
		// open.bigmodel.cn host serves the same surface but is being
		// deprecated; new keys are issued under api.z.ai.
		return "https://api.z.ai/api/paas/v4"
	case "together":
		// Together AI hosts the open-weight catalog (Llama, DeepSeek
		// incl. DeepSeek-OCR, Qwen, Mixtral) plus image gen + embeddings.
		// OpenAI-compatible chat completions at api.together.xyz/v1.
		return "https://api.together.xyz/v1"
	case "grok":
		// xAI Grok. OpenAI-compatible chat completions.
		return "https://api.x.ai/v1"
	case "novita":
		// Novita AI multi-vendor serverless inference.
		return "https://api.novita.ai/v3/openai"
	case "phala":
		// Phala confidential AI — Intel TDX + NVIDIA CC TEEs.
		// `api.redpill.ai` is what Phala's official docs use (Yan @
		// Phala confirmed 2026-05-13 that `api.red-pill.ai` is an
		// alias that also works; we normalized on the no-hyphen form
		// across every reference in the codebase so the AWS vsock-
		// proxy host filter, parent bootstrap, and scraper URL all
		// agree).
		//
		// We route exclusively to the GPU-TEE-attested tier via the
		// `phala/<bare>` model id form (see phalaModelMap below).
		// The upstream-pass-through tier uses a different (redpill)
		// key TR doesn't have.
		return "https://api.redpill.ai/v1"
	case "siliconflow":
		// SiliconFlow Chinese serverless inference (200+ open-weight
		// models). The .com endpoint is the international one; .cn is
		// the China-only mirror.
		return "https://api.siliconflow.com/v1"
	case "tinfoil":
		// Tinfoil TEE-attested confidential inference. The base URL is
		// served from inside an Intel SGX/TDX enclave with attestation
		// document fetchable via the same hostname.
		return "https://inference.tinfoil.sh/v1"
	case "venice":
		// Venice.AI privacy-focused gateway. /api/v1 base path quirk.
		return "https://api.venice.ai/api/v1"
	case "parasail":
		// Parasail serverless inference. OpenAI-compatible.
		return "https://api.parasail.io/v1"
	case "lightning":
		// Lightning AI hosted inference. OpenAI-compatible at the
		// non-standard `/api/v1` path.
		return "https://lightning.ai/api/v1"
	case "gmi":
		// GMI Cloud confidential-GPU inference. OpenAI-compatible.
		return "https://api.gmi-serving.com/v1"
	case "deepinfra":
		// DeepInfra OpenAI-compatible chat completions. Note the
		// `/v1/openai` path (not `/v1`) — DeepInfra namespaces the
		// OpenAI-shape endpoints separately from their native /v1.
		return "https://api.deepinfra.com/v1/openai"
	case "nebius":
		// Nebius Token Factory OpenAI-compatible shared inference.
		return "https://api.tokenfactory.nebius.com/v1"
	case "minimax":
		// MiniMax first-party international endpoint. The minimaxi.com
		// host is for China-region keys; this project key is scoped to
		// the international api.minimax.io endpoint.
		return "https://api.minimax.io/v1"
	default:
		return ""
	}
}

func directModelID(provider, model, upstreamModel string) string {
	resolved := model
	upstreamModel = strings.TrimSpace(upstreamModel)
	// Provider-specific overrides (consulted first). Together hosts
	// open-weight models under their own catalog naming
	// (`Llama-3.3-70B-Instruct-Turbo` etc.) rather than the
	// OpenRouter-canonical lowercase. Without this, every Together-
	// routed request 404s. Maintained as a static table because
	// runtime discovery would mean an extra Together API call at
	// boot — net more code in the auditable enclave surface.
	// Per-provider native-id overrides (consulted first). Each
	// second-source provider — Together, Lightning, GMI, DeepInfra,
	// Parasail, Tinfoil — hosts upstream-author models under its own
	// catalog naming (e.g. `Llama-3.3-70B-Instruct-Turbo` on Together,
	// `lightning-ai/gemma-4-31B-it` on Lightning, `kimi-k2-6` on
	// Tinfoil). Without an explicit map, the generic fall-through
	// below strips the OR-canonical author prefix and ships a bare
	// model id that 404s on the provider's API. The per-provider
	// maps are kept in lock-step with the pricing scrapers at
	// `quill-router/scripts/pricing/providers/<slug>.py`, which are
	// the source of truth for which native ids actually exist today.
	if perProvider, ok := providerNativeModelMaps[provider]; ok {
		key := upstreamModel
		if key == "" {
			key = model
		}
		if mapped, ok := perProvider[stripOpenRouterModelVariant(key)]; ok {
			return mapped
		}
	}
	if providerPreservesAuthorModelID(provider) {
		key := upstreamModel
		if key == "" {
			key = model
		}
		if key != "" {
			return stripOpenRouterModelVariant(key)
		}
	}
	if upstreamModel != "" {
		if mapped, ok := directModelMap[upstreamModel]; ok {
			return stripOpenRouterModelVariant(mapped)
		}
		prefix := provider + "/"
		if strings.HasPrefix(upstreamModel, prefix) {
			resolved = strings.TrimPrefix(upstreamModel, prefix)
			if mapped, ok := directModelMap[resolved]; ok {
				return stripOpenRouterModelVariant(mapped)
			}
			return stripOpenRouterModelVariant(resolved)
		}
		if idx := strings.Index(upstreamModel, "/"); idx >= 0 && idx+1 < len(upstreamModel) {
			resolved = upstreamModel[idx+1:]
			if mapped, ok := directModelMap[resolved]; ok {
				return stripOpenRouterModelVariant(mapped)
			}
			return stripOpenRouterModelVariant(resolved)
		}
		return stripOpenRouterModelVariant(upstreamModel)
	}
	if mapped, ok := directModelMap[model]; ok {
		return stripOpenRouterModelVariant(mapped)
	}
	prefix := provider + "/"
	if strings.HasPrefix(model, prefix) {
		resolved = strings.TrimPrefix(model, prefix)
		return stripOpenRouterModelVariant(resolved)
	}
	if idx := strings.Index(model, "/"); idx >= 0 && idx+1 < len(model) {
		resolved = model[idx+1:]
		return stripOpenRouterModelVariant(resolved)
	}
	return stripOpenRouterModelVariant(resolved)
}

func providerPreservesAuthorModelID(provider string) bool {
	switch provider {
	case "novita", "nebius":
		return true
	default:
		return false
	}
}

func stripOpenRouterModelVariant(model string) string {
	for _, suffix := range []string{":free", ":floor", ":nitro"} {
		if strings.HasSuffix(model, suffix) {
			return strings.TrimSuffix(model, suffix)
		}
	}
	return model
}

// togetherModelMap translates the OpenRouter-canonical model id (what
// the TR control plane sends in the request body) to Together's own
// catalog id. Built once by querying Together's /v1/models against the
// set of Together-served models in src/trusted_router/data/openrouter_snapshot.json
// and refreshed by hand when new Together-hosted models are added.
//
// Anything Together-routed and not in this map falls through to the
// global directModelMap and then to the raw model id — which will 404
// if Together's catalog uses different casing/naming. Backfill on
// demand.
// providerNativeModelMaps is the per-provider OR-canonical →
// provider-native lookup consulted by `directModelID`. Add a new
// provider here when its scraper at
// `quill-router/scripts/pricing/providers/<slug>.py` introduces a
// `_NATIVE_TO_OR_ID` map (i.e. when native ids diverge from OR
// canonical for that provider). Providers absent from this table
// fall through to the generic strip-author logic — fine for any
// upstream whose API accepts the OR-canonical id verbatim.
var providerNativeModelMaps = map[string]map[string]string{
	"together":  togetherModelMap,
	"lightning": lightningModelMap,
	"parasail":  parasailModelMap,
	"deepinfra": deepinfraModelMap,
	"gmi":       gmiModelMap,
	"tinfoil":   tinfoilModelMap,
	"novita":    novitaModelMap,
	"phala":     phalaModelMap,
	"minimax":   minimaxModelMap,
}

var minimaxModelMap = map[string]string{
	"minimax/minimax-m2.7":           "MiniMax-M2.7",
	"minimax/minimax-m2.7-highspeed": "MiniMax-M2.7-highspeed",
	"minimax/minimax-m2.5":           "MiniMax-M2.5",
	"minimax/minimax-m2.5-highspeed": "MiniMax-M2.5-highspeed",
	"minimax/minimax-m2.1":           "MiniMax-M2.1",
	"minimax/minimax-m2.1-highspeed": "MiniMax-M2.1-highspeed",
	"minimax/minimax-m2":             "MiniMax-M2",
}

// togetherModelMap translates OR-canonical model id → Together's own
// catalog id. Together serves open-weight models under their own
// naming (`Llama-3.3-70B-Instruct-Turbo`, `Qwen2.5-7B-Instruct-Turbo`,
// etc.). Kept in lock-step with
// `quill-router/scripts/pricing/providers/together.py`.
var togetherModelMap = map[string]string{
	"deepcogito/cogito-v2.1-671b":       "deepcogito/cogito-v2-1-671b",
	"deepseek/deepseek-v3":              "deepseek-ai/DeepSeek-V3",
	"deepseek/deepseek-v3-ocr":          "deepseek-ai/DeepSeek-V3-OCR",
	"deepseek/deepseek-v4-pro":          "deepseek-ai/DeepSeek-V4-Pro",
	"google/gemma-3n-e4b-it":            "google/gemma-3n-E4B-it",
	"google/gemma-4-31b-it":             "google/gemma-4-31B-it",
	"liquid/lfm-2-24b-a2b":              "LiquidAI/LFM2-24B-A2B",
	"meta-llama/llama-3-8b-chat":        "meta-llama/Llama-3-8b-chat-hf",
	"meta-llama/llama-3-8b-instruct":    "meta-llama/Meta-Llama-3-8B-Instruct-Lite",
	"meta-llama/llama-3.1-8b-instruct":  "meta-llama/Llama-3.1-8B-Instruct-Turbo",
	"meta-llama/llama-3.1-70b-instruct": "meta-llama/Llama-3.1-70B-Instruct-Turbo",
	"meta-llama/llama-3.3-70b-instruct": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
	"meta-llama/llama-guard-4-12b":      "meta-llama/Llama-Guard-4-12B",
	"minimax/minimax-m2.7":              "MiniMaxAI/MiniMax-M2.7",
	"mistralai/mixtral-8x7b-instruct":   "mistralai/Mixtral-8x7B-Instruct-v0.1",
	"moonshotai/kimi-k2-instruct":       "moonshotai/Kimi-K2-Instruct",
	"moonshotai/kimi-k2.5":              "moonshotai/Kimi-K2.5",
	"moonshotai/kimi-k2.6":              "moonshotai/Kimi-K2.6",
	"qwen/qwen-2.5-7b-instruct":         "Qwen/Qwen2.5-7B-Instruct-Turbo",
	"qwen/qwen-2.5-72b-instruct":        "Qwen/Qwen2.5-72B-Instruct-Turbo",
	"qwen/qwen3-coder":                  "Qwen/Qwen3-Coder-Next-FP8",
	"qwen/qwen3-coder-next":             "Qwen/Qwen3-Coder-Next-FP8",
	"qwen/qwen3.5-397b-a17b":            "Qwen/Qwen3.5-397B-A17B",
	"qwen/qwen3.5-9b":                   "Qwen/Qwen3.5-9B",
	"z-ai/glm-5":                        "zai-org/GLM-5",
	"z-ai/glm-5.1":                      "zai-org/GLM-5.1",
}

// lightningModelMap maps OR-canonical → Lightning AI native.
// Lightning serves models under a `lightning-ai/...` author prefix
// (regardless of upstream author) and preserves upstream caps
// (`31B`, `26B-A4B`). Source:
// `quill-router/scripts/pricing/providers/lightning.py`.
var lightningModelMap = map[string]string{
	"google/gemma-4-31b-it":             "lightning-ai/gemma-4-31B-it",
	"google/gemma-4-26b-a4b-it":         "lightning-ai/gemma-4-26B-A4B-it",
	"meta-llama/llama-3.3-70b-instruct": "lightning-ai/llama-3.3-70b",
	"deepseek/deepseek-v3.1":            "lightning-ai/DeepSeek-V3.1",
}

// parasailModelMap maps OR-canonical → Parasail native. Parasail's
// /v1/models exposes BOTH a `parasail-*` slug AND the upstream-
// author form for each model; we always pick the `parasail-*`
// slug because (a) it pins billing to Parasail's own tier and
// (b) it's case-stable (the upstream-author form Parasail accepts
// is mixed-case like `meta-llama/Llama-3.3-70B-Instruct`, which
// doesn't match our lowercase OR canonical and would still need
// translation).
//
// Source of truth: live probe of https://api.parasail.io/v1/models
// on 2026-05-12 + dashboard pricing pasted by operator. Kept in
// lock-step with `quill-router/scripts/pricing/providers/parasail.py`.
// When a model is added there, mirror the entry here.
var parasailModelMap = map[string]string{
	// gemma
	"google/gemma-4-31b-it":     "parasail-gemma-4-31b-it",
	"google/gemma-4-26b-a4b-it": "parasail-gemma-4-26b-a4b-it",
	"google/gemma-3-27b-it":     "parasail-gemma3-27b-it",
	// llama
	"meta-llama/llama-3.3-70b-instruct": "parasail-llama-33-70b-fp8",
	"meta-llama/llama-4-maverick":       "parasail-llama-4-maverick-instruct-fp8",
	// qwen
	"qwen/qwen2.5-vl-72b-instruct":     "parasail-qwen25-vl-72b-instruct",
	"qwen/qwen3-vl-235b-a22b-instruct": "parasail-qwen3-vl-235b-a22b-instruct",
	"qwen/qwen3-vl-8b-instruct":        "parasail-qwen3vl-8b-instruct",
	"qwen/qwen3-235b-a22b-2507":        "parasail-qwen3-235b-a22b-instruct-2507",
	"qwen/qwen3-coder-next":            "parasail-qwen3-coder-next",
	"qwen/qwen3.5-397b-a17b":           "parasail-qwen35-397b-a17b",
	"qwen/qwen3.5-35b-a3b":             "parasail-qwen3p5-35b-a3b",
	"qwen/qwen3.6-35b-a3b":             "parasail-qwen3p6-35b-a3b",
	"qwen/qwen3-next-80b-a3b-instruct": "parasail-qwen-3-next-80b-instruct",
	// deepseek
	"deepseek/deepseek-v3.2":     "parasail-deepseek-v32",
	"deepseek/deepseek-v4-flash": "parasail-deepseek-v4-flash",
	"deepseek/deepseek-v4-pro":   "parasail-deepseek-v4-pro",
	// z-ai / glm
	"z-ai/glm-5":   "parasail-glm-5",
	"z-ai/glm-5.1": "parasail-glm-51",
	"z-ai/glm-4.7": "parasail-glm47",
	// moonshot
	"moonshotai/kimi-k2.5": "parasail-kimi-k25",
	"moonshotai/kimi-k2.6": "parasail-kimi-k26",
	// minimax
	"minimax/minimax-m2.5": "parasail-minimax-m25",
	// gpt-oss
	"openai/gpt-oss-120b": "parasail-gpt-oss-120b",
	"openai/gpt-oss-20b":  "parasail-gpt-oss-20b",
	// mistral
	"mistralai/mistral-small-3.2-24b-instruct": "parasail-mistral-small-32-24b",
	// thedrummer / arcee / stepfun / bytedance
	"thedrummer/cydonia-24b-v4.1":     "parasail-cydonia-24-v41",
	"thedrummer/skyfall-36b-v2":       "parasail-skyfall-36b-v2-fp8",
	"stepfun/step-3.5-flash":          "parasail-stepfun35-flash",
	"arcee-ai/trinity-large-thinking": "parasail-trinity-large-thinking",
	"bytedance/ui-tars-1.5-7b":        "parasail-ui-tars-1p5-7b",
}

// deepinfraModelMap maps OR-canonical → DeepInfra native. DeepInfra
// keeps the upstream-author path but capitalizes model-size suffixes
// (`Gemma-4-31B`, `Llama-3.3-70B`) and re-prefixes DeepSeek/Qwen
// under their own org names (`deepseek-ai/`, `Qwen/`). Source:
// `quill-router/scripts/pricing/providers/deepinfra.py`.
var deepinfraModelMap = map[string]string{
	"google/gemma-4-31b-it":             "google/gemma-4-31B-it",
	"google/gemma-4-26b-a4b-it":         "google/gemma-4-26B-A4B-it",
	"google/gemma-3-27b-it":             "google/gemma-3-27b-it",
	"google/gemma-3-12b-it":             "google/gemma-3-12b-it",
	"google/gemma-3-4b-it":              "google/gemma-3-4b-it",
	"meta-llama/llama-3.1-70b-instruct": "meta-llama/Meta-Llama-3.1-70B-Instruct",
	"meta-llama/llama-3.3-70b-instruct": "meta-llama/Llama-3.3-70B-Instruct",
	"deepseek/deepseek-v3.1":            "deepseek-ai/DeepSeek-V3.1",
	"qwen/qwen3.5-27b":                  "Qwen/Qwen3.5-27B",
}

// gmiModelMap maps OR-canonical → GMI Cloud native. Two patterns:
// (a) gemma-4 / OpenAI / Anthropic models keep the full
// `<author>/<model>` path verbatim, but the generic
// `directModelID` fall-through would strip the author prefix
// down to a bare slug and 404. (b) DeepSeek and z-ai are
// re-prefixed under their org names (`deepseek-ai/`, `zai-org/`).
// Source: `quill-router/scripts/pricing/providers/gmi.py`.
var gmiModelMap = map[string]string{
	"google/gemma-4-31b-it":     "google/gemma-4-31b-it",
	"google/gemma-4-26b-a4b-it": "google/gemma-4-26b-a4b-it",
	"deepseek/deepseek-v4-pro":  "deepseek-ai/DeepSeek-V4-Pro",
	"deepseek/deepseek-v3.1":    "deepseek-ai/DeepSeek-V3.1",
	"z-ai/glm-5":                "zai-org/GLM-5-FP8",
	"z-ai/glm-5.1":              "zai-org/GLM-5.1-FP8",
	"anthropic/claude-opus-4.7": "anthropic/claude-opus-4.7",
	"openai/gpt-5.4-nano":       "openai/gpt-5.4-nano",
	"openai/gpt-5.5":            "openai/gpt-5.5",
}

// novitaModelMap maps OR-canonical → Novita native. Novita's live
// /openai/v1/models endpoint uses full author-prefixed ids
// (`moonshotai/kimi-k2.6`, `deepseek/deepseek-v4-flash`, etc.).
// `providerPreservesAuthorModelID("novita")` handles the general case
// by passing those ids through verbatim. This explicit map remains for
// the earliest audited gemma-4 regression and as a place to add future
// Novita-specific exceptions if their catalog ever diverges.
var novitaModelMap = map[string]string{
	"google/gemma-4-31b-it":     "google/gemma-4-31b-it",
	"google/gemma-4-26b-a4b-it": "google/gemma-4-26b-a4b-it",
}

// phalaModelMap maps OR-canonical → Phala native.
//
// The 2026-05-12 first attempt routed Phala via the
// upstream-author form (`openai/gpt-5.5`, `anthropic/claude-haiku-4.5`,
// etc.) because /v1/models lists both forms. That returned
// `{"error":{"message":"Invalid API key provided"}}` on every chat
// request even though /v1/models worked with the same key.
//
// Root cause uncovered from Phala's docs at
// https://docs.phala.com/phala-cloud/confidential-ai/confidential-model/confidential-ai-api :
// their example uses `"model": "phala/deepseek-chat-v3-0324"`. The
// `phala/` prefix selects the GPU-TEE-attested confidential tier
// (which our key is entitled to); the upstream-author forms in
// /v1/models go to a non-TEE pass-through tier that our key is
// NOT entitled to, hence 401. Confidential AI keys + TEE
// inference is the entire product reason we use Phala — match it.
//
// Source: live probe of api.redpill.ai/v1/models + Phala
// confidential-ai-api docs on 2026-05-13. Add new entries when
// Phala adds new `phala/...` model aliases.
var phalaModelMap = map[string]string{
	"google/gemma-3-27b-it":            "phala/gemma-3-27b-it",
	"minimax/minimax-m2.5":             "phala/minimax-m2.5",
	"moonshotai/kimi-k2.5":             "phala/kimi-k2.5",
	"moonshotai/kimi-k2.6":             "phala/kimi-k2.6",
	"openai/gpt-oss-120b":              "phala/gpt-oss-120b",
	"openai/gpt-oss-20b":               "phala/gpt-oss-20b",
	"qwen/qwen-2.5-7b-instruct":        "phala/qwen-2.5-7b-instruct",
	"qwen/qwen2.5-vl-72b-instruct":     "phala/qwen2.5-vl-72b-instruct",
	"qwen/qwen3-vl-30b-a3b-instruct":   "phala/qwen3-vl-30b-a3b-instruct",
	"qwen/qwen3.5-27b":                 "phala/qwen3.5-27b",
	"qwen/qwen3.5-397b-a17b":           "phala/qwen3.5-397b-a17b",
	"qwen/qwen3-coder-next":            "phala/qwen3-coder-next",
	"qwen/qwen3-30b-a3b-instruct-2507": "phala/qwen3-30b-a3b-instruct-2507",
	"z-ai/glm-4.7":                     "phala/glm-4.7",
	"z-ai/glm-4.7-flash":               "phala/glm-4.7-flash",
	"z-ai/glm-5":                       "phala/glm-5",
	"z-ai/glm-5.1":                     "phala/glm-5.1",
	"deepseek/deepseek-v3.2":           "phala/deepseek-v3.2",
	"deepseek/deepseek-chat-v3.1":      "phala/deepseek-chat-v3.1",
	"xiaomi/mimo-v2-flash":             "phala/mimo-v2-flash",
}

// tinfoilModelMap maps OR-canonical → Tinfoil native. Tinfoil
// flattens everything to a bare slug and replaces dots with
// dashes (`kimi-k2.6` → `kimi-k2-6`, `glm-5.1` → `glm-5-1`).
// Without this map, every Tinfoil-routed request for a model
// containing a dot in its version silently 404s. Source:
// `quill-router/scripts/pricing/providers/tinfoil.py`.
var tinfoilModelMap = map[string]string{
	"moonshotai/kimi-k2.6":              "kimi-k2-6",
	"z-ai/glm-5.1":                      "glm-5-1",
	"deepseek/deepseek-v4-pro":          "deepseek-v4-pro",
	"google/gemma-4-31b":                "gemma4-31b",
	"qwen/qwen3-vl-30b":                 "qwen3-vl-30b",
	"meta-llama/llama-3.3-70b-instruct": "llama3-3-70b",
	"openai/gpt-oss-120b":               "gpt-oss-120b",
	"mistralai/voxtral-small-24b":       "voxtral-small-24b",
	"openai/whisper-large-v3-turbo":     "whisper-large-v3-turbo",
	"qwen/qwen3-tts":                    "qwen3-tts",
	"nomic-ai/nomic-embed-text":         "nomic-embed-text",
}

var directModelMap = map[string]string{
	"anthropic/claude-opus-4.7":        "claude-opus-4-7",
	"anthropic/claude-sonnet-4.6":      "claude-sonnet-4-6",
	"anthropic/claude-haiku-4.5":       "claude-haiku-4-5",
	"anthropic/claude-3-5-sonnet":      "claude-3-5-sonnet-20241022",
	"meta-llama/llama-3.1-8b-instruct": "llama3.1-8b",
	"llama-3.1-8b-instruct":            "llama3.1-8b",
	"openai/gpt-oss-120b":              "gpt-oss-120b",
	"qwen/qwen3-235b-a22b-2507":        "qwen-3-235b-a22b-instruct-2507",
	"z-ai/glm-4.7":                     "zai-glm-4.7",
	"openai/gpt-4o-mini":               "gpt-4o-mini",
	"google/gemini-1.5-flash":          "gemini-1.5-flash",
	"vertex/gemini-2.5-flash":          "gemini-2.5-flash",
}

func normalizeDirectProvider(provider string) string {
	slug := strings.ToLower(strings.TrimSpace(provider))
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "_", "-")
	switch slug {
	case "google", "google-ai", "gemini":
		return "gemini"
	case "moonshot", "moonshot-ai", "moonshotai", "kimi":
		return "kimi"
	case "mistral-ai", "mistralai", "mistral":
		return "mistral"
	case "z-ai", "zhipu", "zhipuai", "zai":
		return "zai"
	case "x-ai", "xai", "grok":
		return "grok"
	case "novita", "novita-ai":
		return "novita"
	case "phala", "redpill", "red-pill":
		return "phala"
	case "silicon-flow", "siliconflow":
		return "siliconflow"
	case "tinfoil", "tinfoil-sh":
		return "tinfoil"
	case "venice", "venice-ai":
		return "venice"
	case "parasail", "parasail-ai", "parasail-io":
		return "parasail"
	case "lightning", "lightning-ai":
		return "lightning"
	case "gmi", "gmi-cloud", "gmicloud":
		return "gmi"
	case "deepinfra", "deep-infra", "deep_infra":
		return "deepinfra"
	case "nebius", "nebius-ai", "nebius-ai-studio", "tokenfactory", "token-factory":
		return "nebius"
	case "minimax", "mini-max", "minimax-ai", "minimaxai":
		return "minimax"
	default:
		return slug
	}
}

// defaultHTTPClient returns the default outbound HTTP client used by
// every LLM-provider client (anthropic, openai-compatible, etc.).
//
// On GCP-side enclaves this dials directly over the network — the
// Confidential Space VM has plain internet egress.
//
// On AWS-side enclaves (cloud_aws build tag), the Nitro Enclave has
// no network at all; outbound HTTPS must travel via vsock to the
// parent host's `vsock-proxy` daemon. The cloud_aws variant of this
// function (in http_client_aws.go) returns a vsockhttp-backed client
// with a Tunnel per upstream hostname.
//
// See:
//   - http_client_direct.go     (!cloud_aws — net.Dialer)
//   - http_client_aws.go        (cloud_aws — vsockhttp tunnel map)
//   - parent's vsock-proxy.yaml (matching CID:port allowlist)
