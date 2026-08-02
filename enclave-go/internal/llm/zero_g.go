//go:build llm_multi

package llm

import (
	"context"
	"io"
	"net/http"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// zeroGClient supports both formats published by 0G's account catalog.
// Claude routes accept Anthropic Messages only; every other chat model uses
// the OpenAI-compatible chat-completions endpoint.
type zeroGClient struct {
	openAI  *openAICompatibleClient
	baseURL string
	apiKey  string
	httpc   *http.Client
}

func newZeroG(apiKey string) *zeroGClient {
	return newZeroGAt(directBaseURL("zero-g"), apiKey, defaultHTTPClient())
}

func newZeroGAt(baseURL string, apiKey string, httpc *http.Client) *zeroGClient {
	baseURL = strings.TrimRight(baseURL, "/")
	apiKey = strings.TrimSpace(apiKey)
	return &zeroGClient{
		openAI: &openAICompatibleClient{
			provider: "zero-g",
			baseURL:  baseURL,
			apiKey:   apiKey,
			httpc:    httpc,
		},
		baseURL: baseURL,
		apiKey:  apiKey,
		httpc:   httpc,
	}
}

func (c *zeroGClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	option := firstOptions(options)
	if zeroGUsesAnthropicFormat(req, option) {
		return invokeAnthropicCompatibleStreamingWithClient(
			ctx,
			c.httpc,
			"zero-g",
			c.baseURL+"/messages",
			true,
			req,
			body,
			out,
			c.apiKey,
			option.UpstreamModel,
		)
	}
	return c.openAI.InvokeStreaming(ctx, req, body, out, options...)
}

func zeroGUsesAnthropicFormat(req *qtypes.OpenAIChatRequest, option InvokeOptions) bool {
	upstream := strings.ToLower(strings.TrimSpace(option.UpstreamModel))
	if strings.HasPrefix(upstream, "claude-") {
		return true
	}
	return req != nil && strings.HasPrefix(strings.ToLower(req.Model), "anthropic/")
}
