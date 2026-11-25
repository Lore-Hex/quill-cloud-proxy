//go:build llm_multi

package llm

import (
	"context"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func (c *openAICompatibleClient) InvokeRerank(ctx context.Context, req *qtypes.RerankRequest, options ...InvokeOptions) (*qtypes.RerankResponse, error) {
	if c.provider != "voyage" {
		return nil, ErrRerankUnsupported
	}
	return invokeRerank(ctx, c.httpc, "voyage", c.baseURL, c.apiKey, req, firstOptions(options))
}

func (c *cohereClient) InvokeRerank(ctx context.Context, req *qtypes.RerankRequest, options ...InvokeOptions) (*qtypes.RerankResponse, error) {
	return invokeRerank(ctx, c.httpc, "cohere", c.baseURL, c.apiKey, req, firstOptions(options))
}

func (m *multiClient) InvokeRerank(ctx context.Context, req *qtypes.RerankRequest, options ...InvokeOptions) (*qtypes.RerankResponse, error) {
	option := firstOptions(options)
	switch normalizeDirectProvider(option.Provider) {
	case "voyage":
		if m.voyage == nil {
			return nil, ErrRerankUnsupported
		}
		return m.voyage.InvokeRerank(ctx, req, options...)
	case "cohere":
		if m.cohere == nil {
			return nil, ErrRerankUnsupported
		}
		return m.cohere.InvokeRerank(ctx, req, options...)
	default:
		return nil, ErrRerankUnsupported
	}
}
