package llm

import "net/http"

// NewProviderHTTPClient returns the build-specific upstream transport used by
// provider adapters. On GCP it dials directly; on Nitro it stays inside TLS and
// crosses the parent only through the explicit vsock hostname allowlist.
func NewProviderHTTPClient() *http.Client {
	return defaultHTTPClient()
}
