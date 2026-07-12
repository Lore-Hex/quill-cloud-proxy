//go:build llm_multi

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Cohere is NOT OpenAI-shaped. Its embeddings API is POST /v2/embed with
// {model, texts, input_type, embedding_types} and returns
// {embeddings:{float:[[...]]}, meta:{billed_units:{input_tokens}}}. We adapt
// that to the OpenAI embeddings envelope. Cohere chat (command-*) is a
// different non-OpenAI shape and is not wired — TR only catalogs Cohere
// embedding models today.
const cohereBaseURL = "https://api.cohere.com/v2"

type cohereClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func cohereEmbeddingWirePayload(
	req *qtypes.EmbeddingRequest,
	option InvokeOptions,
) (map[string]any, error) {
	inputs := req.Inputs()
	if len(inputs) == 0 {
		return nil, fmt.Errorf("llm/cohere: empty embedding input")
	}
	inputType := strings.TrimSpace(req.InputType)
	if inputType == "" {
		inputType = "search_document"
	}
	return map[string]any{
		"model":           embeddingUpstreamModel("cohere", req.Model, option.UpstreamModel),
		"texts":           inputs,
		"input_type":      inputType,
		"embedding_types": []string{"float"},
	}, nil
}

func newCohere(apiKey string) *cohereClient {
	return &cohereClient{
		apiKey:  strings.TrimSpace(apiKey),
		baseURL: cohereBaseURL,
		httpc:   defaultHTTPClient(),
	}
}

// InvokeStreaming satisfies the Client interface so cohere can sit in the
// multi dispatcher, but chat is not served — only embeddings.
func (c *cohereClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	return fmt.Errorf("llm/cohere: chat not supported (embeddings only)")
}

func (c *cohereClient) InvokeEmbedding(
	ctx context.Context,
	req *qtypes.EmbeddingRequest,
	options ...InvokeOptions,
) (*qtypes.EmbeddingResponse, error) {
	option := firstOptions(options)
	apiKey := c.apiKey
	if option.ProviderAPIKey != "" {
		apiKey = option.ProviderAPIKey
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("llm/cohere: missing api key")
	}
	payload, err := cohereEmbeddingWirePayload(req, option)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("llm/cohere: marshal body: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/embed", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "TrustedRouter/1.0")
	httpc := c.httpc
	if httpc == nil {
		httpc = defaultHTTPClient()
	}
	resp, err := httpc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm/cohere: invoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return nil, fmt.Errorf("llm/cohere: read error body: %w", readErr)
		}
		return nil, &upstreamHTTPError{status: resp.StatusCode, body: string(errBody)}
	}
	var parsed struct {
		Embeddings struct {
			Float [][]float64 `json:"float"`
		} `json:"embeddings"`
		Meta struct {
			BilledUnits struct {
				InputTokens int `json:"input_tokens"`
			} `json:"billed_units"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("llm/cohere: decode embeddings response: %w", err)
	}
	data := make([]qtypes.EmbeddingData, 0, len(parsed.Embeddings.Float))
	for index, vector := range parsed.Embeddings.Float {
		raw, err := json.Marshal(vector)
		if err != nil {
			return nil, fmt.Errorf("llm/cohere: marshal embedding: %w", err)
		}
		data = append(data, qtypes.EmbeddingData{
			Object:    "embedding",
			Embedding: raw,
			Index:     index,
		})
	}
	promptTokens := parsed.Meta.BilledUnits.InputTokens
	if promptTokens <= 0 {
		promptTokens = qtypes.EstimateEmbeddingInputTokens(req.Inputs())
	}
	return &qtypes.EmbeddingResponse{
		Object: "list",
		Data:   data,
		Model:  req.Model,
		Usage:  qtypes.EmbeddingUsage{PromptTokens: promptTokens, TotalTokens: promptTokens},
	}, nil
}
