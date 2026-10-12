//go:build llm_multi

package llm

import (
	"context"
	"io"
	"net/http"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const azureAnthropicMessagesURL = "https://trustedrouter-foundry-eastus2.services.ai.azure.com/anthropic/v1/messages"
const azureDecisionBaseURL = "https://trustedrouter-foundry-eastus2.services.ai.azure.com/providers/microsoft/v1"

// Azure Foundry exposes one account key across fixed, account-scoped
// surfaces: OpenAI-compatible models use /openai/v1 with api-key auth, while
// Azure-hosted Claude deployments use the native Anthropic Messages protocol.
// The endpoint and protocol choice are enclave-owned; neither is caller input.
type azureClient struct {
	openAI    *openAICompatibleClient
	anthropic *anthropicClient
	decision  *openAICompatibleClient
}

func newAzure(apiKey string) *azureClient {
	openAI := newOpenAICompatible("azure", apiKey)
	anthropic := newAnthropicAt(
		"azure",
		azureAnthropicMessagesURL,
		apiKey,
		true,
	)
	openAI.httpc = azurePinnedHTTPClient(openAI.httpc)
	anthropic.httpc = azurePinnedHTTPClient(anthropic.httpc)
	decision := newOpenAICompatible("azure", apiKey)
	decision.baseURL = azureDecisionBaseURL
	decision.httpc = azurePinnedHTTPClient(decision.httpc)
	return &azureClient{openAI: openAI, anthropic: anthropic, decision: decision}
}

func (c *azureClient) InvokeDecide(ctx context.Context, req *DecideRequest, options ...InvokeOptions) (*DecideResponse, error) {
	if c == nil || c.decision == nil || req == nil || req.Model != "microsoft/microsoft-decision-1" || len(req.Images) != 0 {
		return nil, &DecideError{Provider: "azure", Class: DecideErrConfig}
	}
	option := firstOptions(options)
	if option.UpstreamModel != "tr-decision-1" {
		return nil, &DecideError{Provider: "azure", Class: DecideErrConfig}
	}
	option.Provider = "azure"
	return c.decision.InvokeDecide(ctx, req, option)
}

// azurePinnedHTTPClient preserves the cloud-specific transport and streaming
// timeout while refusing every redirect. Go copies non-standard headers such
// as api-key and x-api-key across redirects; following even a same-service 3xx
// could therefore replay the account credential to a different authority.
// Azure endpoints are enclave-owned and fixed, so a redirect is always an
// upstream failure that the gateway must surface rather than follow.
func azurePinnedHTTPClient(httpc *http.Client) *http.Client {
	if httpc == nil {
		httpc = defaultHTTPClient()
	}
	pinned := *httpc
	pinned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &pinned
}

func (c *azureClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	option := firstOptions(options)
	requestedModel := ""
	if req != nil {
		requestedModel = req.Model
	}
	if azureUsesAnthropicWire(option.UpstreamModel, requestedModel) {
		return c.anthropic.InvokeStreaming(ctx, req, body, out, options...)
	}
	return c.openAI.InvokeStreaming(ctx, req, body, out, options...)
}

func azureUsesAnthropicWire(upstreamModel, requestedModel string) bool {
	for _, model := range []string{upstreamModel, requestedModel} {
		model = strings.ToLower(strings.TrimSpace(model))
		if i := strings.LastIndex(model, "/"); i >= 0 {
			model = model[i+1:]
		}
		if strings.HasPrefix(model, "claude-") {
			return true
		}
	}
	return false
}
