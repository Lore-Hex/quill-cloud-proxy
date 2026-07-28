//go:build llm_multi

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const googleAIStudioNativeBaseURL = "https://generativelanguage.googleapis.com/v1beta"

// aiStudioGeminiClient uses Gemini's native generateContent API. Google AI
// Studio's OpenAI-compatible API rejects generated image parts, so image
// models use this client while text and embeddings retain their established
// compatibility paths.
type aiStudioGeminiClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func newAIStudioGemini(boot *qtypes.BootstrapData) *aiStudioGeminiClient {
	return &aiStudioGeminiClient{
		apiKey:  strings.TrimSpace(boot.GeminiAPIKey),
		baseURL: googleAIStudioNativeBaseURL,
		httpc:   defaultHTTPClient(),
	}
}

func (c *aiStudioGeminiClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if req == nil {
		return fmt.Errorf("llm/google-ai-studio: request is required")
	}
	option := firstOptions(options)
	apiKey := strings.TrimSpace(option.ProviderAPIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(c.apiKey)
	}
	if apiKey == "" {
		return fmt.Errorf("llm/google-ai-studio: missing api key")
	}

	modelID := directModelID("google-ai-studio", req.Model, option.UpstreamModel)
	if modelID == "" {
		return fmt.Errorf("llm/google-ai-studio: missing upstream model")
	}
	payload, err := vertexGeminiPayload(ctx, req, body, modelID)
	if err != nil {
		return err
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("llm/google-ai-studio: marshal body: %w", err)
	}

	baseURL := strings.TrimRight(c.baseURL, "/")
	endpoint := fmt.Sprintf(
		"%s/models/%s:streamGenerateContent?alt=sse",
		baseURL,
		url.PathEscape(modelID),
	)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("x-goog-api-key", apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("User-Agent", "TrustedRouter/1.0")

	httpc := c.httpc
	if httpc == nil {
		httpc = defaultHTTPClient()
	}
	resp, err := httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/google-ai-studio: invoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("llm/google-ai-studio: read error body: %w", readErr)
		}
		return &upstreamHTTPError{status: resp.StatusCode, body: string(errBody)}
	}
	return translateGeminiStreamToAnthropic(resp.Body, out)
}

func googleAIStudioNeedsNativeImage(req *qtypes.OpenAIChatRequest, option InvokeOptions) bool {
	if req == nil {
		return false
	}
	modelID := directModelID("google-ai-studio", req.Model, option.UpstreamModel)
	return vertexGeminiImageModel(modelID)
}
