//go:build llm_zai || llm_multi

// Direct Z.AI / Zhipu (GLM models) backend. Same shape as kimi.go: Quill-
// managed API key from BootstrapData.ZAIAPIKey, OpenAI-compatible upstream
// at https://api.z.ai/api/paas/v4/chat/completions, response stream
// translated through the shared OpenAI→Anthropic helper.
package llm

import (
	"context"
	"io"
	"net/http"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type zaiClient struct {
	apiKey string
	httpc  *http.Client
}

func newZAI(boot *qtypes.BootstrapData) *zaiClient {
	return &zaiClient{
		apiKey: strings.TrimSpace(boot.ZAIAPIKey),
		httpc:  pooledHTTPClient(defaultStreamingHTTPTimeout),
	}
}

func (c *zaiClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if handled, err := invokeBYOKStreaming(ctx, req, body, out, firstOptions(options)); handled {
		return err
	}
	return InvokeOpenAICompatibleStreaming(ctx, "zai", directBaseURL("zai"), c.apiKey, req, body, out, firstOptions(options).UpstreamModel)
}
