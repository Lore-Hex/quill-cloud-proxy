//go:build llm_multi

package llm

import (
	"context"
	"strings"
)

// InvokeDecide dispatches a hosted decision request to the direct provider the
// control plane assigned. Regolo also accepts the authorized BYOK credential
// without requiring an operator-funded client.
// A provider with no client is one whose key this cloud was not given: a
// config failure, which the route answers by moving to the next host.
func (m *multiClient) InvokeDecide(ctx context.Context, req *DecideRequest, options ...InvokeOptions) (*DecideResponse, error) {
	option := firstOptions(options)
	provider := normalizeDirectProvider(option.Provider)
	if provider == "tinfoil" {
		if m.tinfoil == nil {
			return nil, &DecideError{Provider: provider, Class: DecideErrConfig}
		}
		return m.tinfoil.InvokeDecide(ctx, req, options...)
	}
	if provider == "regolo" && (option.ProviderAPIKey != "" || strings.EqualFold(option.UsageType, "BYOK")) {
		return newOpenAICompatible(provider, "").InvokeDecide(ctx, req, options...)
	}
	if provider == "azure" {
		return m.azure.InvokeDecide(ctx, req, options...)
	}
	if client := m.direct[provider]; client != nil {
		return client.InvokeDecide(ctx, req, options...)
	}
	return nil, &DecideError{Provider: provider, Class: DecideErrConfig}
}
