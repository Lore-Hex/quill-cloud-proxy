package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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
	switch provider {
	case "anthropic":
		return true, invokeAnthropicBYOKStreaming(ctx, req, body, out, options.ProviderAPIKey, options.UpstreamModel)
	case "openai", "cerebras", "deepseek", "mistral", "kimi", "gemini", "zai":
		return true, invokeOpenAICompatibleBYOKStreaming(ctx, provider, req, body, out, options.ProviderAPIKey, options.UpstreamModel)
	default:
		return true, fmt.Errorf("llm/byok: unsupported provider %q", options.Provider)
	}
}

type openAICompatibleRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Stream      bool          `json:"stream"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature *float64      `json:"temperature,omitempty"`
	TopP        *float64      `json:"top_p,omitempty"`
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
	msgs := openAICompatibleMessages(body)
	reqBody := openAICompatibleRequest{
		Model:       directModelID(provider, req.Model, upstreamModel),
		Messages:    msgs,
		Stream:      true,
		MaxTokens:   body.MaxTokens,
		Temperature: body.Temperature,
		TopP:        body.TopP,
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
		Model       string                    `json:"model"`
		Messages    []qtypes.AnthropicMessage `json:"messages"`
		System      string                    `json:"system,omitempty"`
		MaxTokens   int                       `json:"max_tokens"`
		Temperature *float64                  `json:"temperature,omitempty"`
		TopP        *float64                  `json:"top_p,omitempty"`
		Stream      bool                      `json:"stream"`
	}{
		Model:       directModelID("anthropic", req.Model, upstreamModel),
		Messages:    messages,
		System:      body.System,
		MaxTokens:   body.MaxTokens,
		Temperature: body.Temperature,
		TopP:        body.TopP,
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

func openAICompatibleMessages(body *qtypes.AnthropicMessagesRequest) []chatMessage {
	msgs := make([]chatMessage, 0, len(body.Messages)+1)
	if body.System != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: body.System})
	}
	for _, message := range body.Messages {
		msgs = append(msgs, chatMessage{Role: message.Role, Content: message.Content})
	}
	return msgs
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
	default:
		return ""
	}
}

func directModelID(provider, model, upstreamModel string) string {
	resolved := model
	upstreamModel = strings.TrimSpace(upstreamModel)
	if upstreamModel != "" {
		prefix := provider + "/"
		if strings.HasPrefix(upstreamModel, prefix) {
			resolved = strings.TrimPrefix(upstreamModel, prefix)
			return stripOpenRouterModelVariant(resolved)
		}
		if idx := strings.Index(upstreamModel, "/"); idx >= 0 && idx+1 < len(upstreamModel) {
			resolved = upstreamModel[idx+1:]
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

func stripOpenRouterModelVariant(model string) string {
	for _, suffix := range []string{":free", ":floor", ":nitro"} {
		if strings.HasSuffix(model, suffix) {
			return strings.TrimSuffix(model, suffix)
		}
	}
	return model
}

var directModelMap = map[string]string{
	"anthropic/claude-opus-4.7":   "claude-opus-4-7",
	"anthropic/claude-sonnet-4.6": "claude-sonnet-4-6",
	"anthropic/claude-haiku-4.5":  "claude-haiku-4-5",
	"anthropic/claude-3-5-sonnet": "claude-3-5-sonnet-20241022",
	"openai/gpt-4o-mini":          "gpt-4o-mini",
	"google/gemini-1.5-flash":     "gemini-1.5-flash",
	"vertex/gemini-2.5-flash":     "gemini-2.5-flash",
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
	default:
		return slug
	}
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Minute}
}
