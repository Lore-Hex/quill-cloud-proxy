//go:build !cloud_aws

// defaultHTTPClient — direct-dial variant for non-AWS builds (GCP
// Confidential Space, dev/test). Just wraps pooledHTTPClient.
//
// The cloud_aws variant lives in http_client_aws.go and returns a
// vsockhttp-backed client because Nitro Enclaves have no network and
// every outbound dial must hop via the parent's vsock-proxy.

package llm

import "net/http"

func defaultHTTPClient() *http.Client {
	return pooledHTTPClient(defaultStreamingHTTPTimeout)
}
