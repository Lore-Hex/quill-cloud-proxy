package llm

import "net/http"

// NewProviderHTTPClient returns the build-specific upstream transport used by
// provider adapters. Every cloud enforces the compiled HTTPS host allowlist;
// Nitro additionally crosses the parent only through fixed vsock tunnels.
func NewProviderHTTPClient() *http.Client {
	return defaultHTTPClient()
}
