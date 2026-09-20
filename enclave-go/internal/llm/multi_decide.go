//go:build llm_multi

package llm

import (
	"context"
	"fmt"
)

// InvokeDecide dispatches a hosted decision request to the direct provider the
// control plane assigned. Only bootstrap-keyed direct providers can serve it;
// today that is Vercel AI Gateway (TypeSafe AI's Jev).
func (m *multiClient) InvokeDecide(ctx context.Context, req *DecideRequest, options ...InvokeOptions) (*DecideResponse, error) {
	provider := normalizeDirectProvider(firstOptions(options).Provider)
	if client := m.direct[provider]; client != nil {
		return client.InvokeDecide(ctx, req, options...)
	}
	return nil, fmt.Errorf("llm/multi: provider %q does not serve decision models", provider)
}
