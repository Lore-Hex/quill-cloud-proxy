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

// EmbeddingClient is implemented by gateway clients that can serve
// POST /v1/embeddings. It is intentionally SEPARATE from the Client
// interface so single-backend builds (llm_anthropic, llm_vertex) don't have
// to implement embeddings — the embeddings route does a runtime type
// assertion and 501s if the running build's client doesn't support it.
//
// Embeddings are non-streaming: the upstream returns a complete JSON
// document, which we adapt to the OpenAI embeddings envelope and return.
type EmbeddingClient interface {
	InvokeEmbedding(ctx context.Context, req *qtypes.EmbeddingRequest, options ...InvokeOptions) (*qtypes.EmbeddingResponse, error)
}

// embeddingUpstreamModel resolves the model id sent to the upstream
// provider. It prefers the control-plane-provided UpstreamModel verbatim
// (the catalog already stores the exact provider-native id for each
// embedding endpoint), because directModelID's generic author-strip would
// corrupt author-prefixed ids like "togethercomputer/m2-bert-80M-8k-retrieval"
// or "BAAI/bge-large-en-v1.5" that Together serves under their full name.
func embeddingUpstreamModel(provider, model, upstreamModel string) string {
	if u := strings.TrimSpace(upstreamModel); u != "" {
		return stripOpenRouterModelVariant(u)
	}
	return directModelID(provider, model, "")
}

// InvokeEmbedding implements EmbeddingClient for OpenAI-shaped providers
// (openai, together): POST {baseURL}/embeddings with {model, input}.
func (c *openAICompatibleClient) InvokeEmbedding(
	ctx context.Context,
	req *qtypes.EmbeddingRequest,
	options ...InvokeOptions,
) (*qtypes.EmbeddingResponse, error) {
	option := firstOptions(options)
	provider := c.provider
	if option.Provider != "" {
		provider = normalizeDirectProvider(option.Provider)
	}
	apiKey := c.apiKey
	baseURL := c.baseURL
	// BYOK: the customer's key (resolved upstream) overrides the bootstrap
	// key, and the base URL is re-derived from the provider slug.
	if option.ProviderAPIKey != "" {
		apiKey = option.ProviderAPIKey
		baseURL = directBaseURL(provider)
	}
	httpc, err := c.resolveHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("llm/%s: http client unavailable: %w", provider, err)
	}
	return invokeOpenAICompatibleEmbeddings(ctx, httpc, provider, baseURL, apiKey, req, option.UpstreamModel)
}

func invokeOpenAICompatibleEmbeddings(
	ctx context.Context,
	httpc *http.Client,
	provider, baseURL, apiKey string,
	req *qtypes.EmbeddingRequest,
	upstreamModel string,
) (*qtypes.EmbeddingResponse, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("llm/%s: missing api key", provider)
	}
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("llm/%s: missing base URL", provider)
	}
	inputs := req.Inputs()
	if len(inputs) == 0 {
		return nil, fmt.Errorf("llm/%s: empty embedding input", provider)
	}
	payload := map[string]any{
		"model": embeddingUpstreamModel(provider, req.Model, upstreamModel),
		"input": inputs,
	}
	if req.EncodingFormat != "" {
		payload["encoding_format"] = req.EncodingFormat
	}
	if req.Dimensions != nil {
		payload["dimensions"] = *req.Dimensions
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("llm/%s: marshal body: %w", provider, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/embeddings", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "TrustedRouter/1.0")
	if httpc == nil {
		httpc = defaultHTTPClient()
	}
	resp, err := httpc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm/%s: invoke: %w", provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return nil, fmt.Errorf("llm/%s: read error body: %w", provider, readErr)
		}
		return nil, &upstreamHTTPError{status: resp.StatusCode, body: string(errBody)}
	}
	var parsed struct {
		Data []struct {
			Object    string          `json:"object"`
			Embedding json.RawMessage `json:"embedding"`
			Index     int             `json:"index"`
		} `json:"data"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("llm/%s: decode embeddings response: %w", provider, err)
	}
	data := make([]qtypes.EmbeddingData, 0, len(parsed.Data))
	for _, row := range parsed.Data {
		object := row.Object
		if object == "" {
			object = "embedding"
		}
		data = append(data, qtypes.EmbeddingData{
			Object:    object,
			Embedding: row.Embedding,
			Index:     row.Index,
		})
	}
	promptTokens := parsed.Usage.PromptTokens
	if promptTokens <= 0 {
		promptTokens = qtypes.EstimateEmbeddingInputTokens(inputs)
	}
	return &qtypes.EmbeddingResponse{
		Object: "list",
		Data:   data,
		Model:  req.Model,
		Usage:  qtypes.EmbeddingUsage{PromptTokens: promptTokens, TotalTokens: promptTokens},
	}, nil
}
