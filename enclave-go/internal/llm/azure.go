//go:build llm_multi

package llm

import (
	"context"
	"io"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const azureAnthropicMessagesURL = "https://trustedrouter-foundry-eastus2.services.ai.azure.com/anthropic/v1/messages"

// Azure Foundry exposes one account key across two wire-compatible surfaces:
// OpenAI-compatible models use /openai/v1 with api-key auth, while Azure-hosted
// Claude deployments use the native Anthropic Messages protocol. Keep that
// distinction internal so the control plane still sees one provider route.
type azureClient struct {
	openAI    *openAICompatibleClient
	anthropic *anthropicClient
}

func newAzure(apiKey string) *azureClient {
	return &azureClient{
		openAI: newOpenAICompatible("azure", apiKey),
		anthropic: newAnthropicAt(
			"azure",
			azureAnthropicMessagesURL,
			apiKey,
			true,
		),
	}
}

func (c *azureClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	option := firstOptions(options)
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(option.UpstreamModel)), "claude-") {
		return c.anthropic.InvokeStreaming(ctx, req, body, out, options...)
	}
	return c.openAI.InvokeStreaming(ctx, req, body, out, options...)
}
