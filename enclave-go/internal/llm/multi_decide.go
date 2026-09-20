//go:build llm_multi

package llm

import "context"

// InvokeDecide dispatches a hosted decision request to the direct provider the
// control plane assigned. Only bootstrap-keyed direct providers can serve it;
// today that is TypeSafe AI (Jev's vendor) and Vercel AI Gateway (its relay).
// A provider with no client is one whose key this cloud was not given: a
// config failure, which the route answers by moving to the next host.
func (m *multiClient) InvokeDecide(ctx context.Context, req *DecideRequest, options ...InvokeOptions) (*DecideResponse, error) {
	provider := normalizeDirectProvider(firstOptions(options).Provider)
	if client := m.direct[provider]; client != nil {
		return client.InvokeDecide(ctx, req, options...)
	}
	return nil, &DecideError{Provider: provider, Class: DecideErrConfig}
}
