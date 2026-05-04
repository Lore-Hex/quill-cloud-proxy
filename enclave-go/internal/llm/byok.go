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
		return true, invokeAnthropicBYOKStreaming(ctx, req, body, out, options.ProviderAPIKey)
	case "openai", "cerebras", "deepseek", "mistral", "kimi", "gemini":
		return true, invokeOpenAICompatibleBYOKStreaming(ctx, provider, req, body, out, options.ProviderAPIKey)
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
	Content string `json:"content"`
}

func invokeOpenAICompatibleBYOKStreaming(
	ctx context.Context,
	provider string,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	apiKey string,
) error {
	msgs := openAICompatibleMessages(body)
	reqBody := openAICompatibleRequest{
		Model:       directModelID(provider, req.Model),
		Messages:    msgs,
		Stream:      true,
		MaxTokens:   body.MaxTokens,
		Temperature: body.Temperature,
		TopP:        body.TopP,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("llm/byok: marshal openai-compatible body: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, directBaseURL(provider)+"/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := defaultHTTPClient().Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/byok: %s invoke: %w", provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("llm/byok: read %s error body: %w", provider, readErr)
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
) error {
	reqBody := struct {
		Model       string                    `json:"model"`
		Messages    []qtypes.AnthropicMessage `json:"messages"`
		System      string                    `json:"system,omitempty"`
		MaxTokens   int                       `json:"max_tokens"`
		Temperature *float64                  `json:"temperature,omitempty"`
		TopP        *float64                  `json:"top_p,omitempty"`
		Stream      bool                      `json:"stream"`
	}{
		Model:       directModelID("anthropic", req.Model),
		Messages:    body.Messages,
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
	default:
		return ""
	}
}

func directModelID(provider, model string) string {
	if mapped, ok := directModelMap[model]; ok {
		return mapped
	}
	prefix := provider + "/"
	if strings.HasPrefix(model, prefix) {
		return strings.TrimPrefix(model, prefix)
	}
	if idx := strings.Index(model, "/"); idx >= 0 && idx+1 < len(model) {
		return model[idx+1:]
	}
	return model
}

var directModelMap = map[string]string{
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
	case "moonshot", "moonshot-ai", "kimi":
		return "kimi"
	case "mistral-ai", "mistral":
		return "mistral"
	default:
		return slug
	}
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Minute}
}
