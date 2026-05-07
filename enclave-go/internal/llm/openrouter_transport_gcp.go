//go:build llm_openrouter && cloud_gcp

// GCP Confidential Space variant: direct egress. CSP VMs reach the
// public Internet without a parent-side proxy, so this is just a stock
// http.Client. TLS is still negotiated inside the attested workload —
// the GLB does TCP passthrough, no termination outside.
package llm

import (
	"net/http"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func newOpenRouterHTTPClient(_ *qtypes.BootstrapData) *http.Client {
	return pooledHTTPClient(defaultStreamingHTTPTimeout)
}
