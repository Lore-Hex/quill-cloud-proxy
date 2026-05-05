package llm

import (
	"context"
	"io"
	"net/http"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type openAICompatibleClient struct {
	provider string
	baseURL  string
	apiKey   string
	httpc    *http.Client
}

func newOpenAICompatible(provider string, apiKey string) *openAICompatibleClient {
	provider = normalizeDirectProvider(provider)
	return &openAICompatibleClient{
		provider: provider,
		baseURL:  directBaseURL(provider),
		apiKey:   strings.TrimSpace(apiKey),
		httpc:    defaultHTTPClient(),
	}
}

func (c *openAICompatibleClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if handled, err := invokeBYOKStreaming(ctx, req, body, out, firstOptions(options)); handled {
		return err
	}
	option := firstOptions(options)
	provider := c.provider
	if option.Provider != "" {
		provider = normalizeDirectProvider(option.Provider)
	}
	return invokeOpenAICompatibleStreamingWithClient(
		ctx,
		c.httpc,
		provider,
		c.baseURL,
		c.apiKey,
		req,
		body,
		out,
		option.UpstreamModel,
	)
}
