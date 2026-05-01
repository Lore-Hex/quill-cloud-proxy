//go:build llm_openrouter && cloud_aws

// AWS Nitro variant: route OpenRouter traffic over the parent's
// vsock-proxy tunnel. The enclave has no direct egress, so the parent
// runs `vsock-proxy 8004 openrouter.ai 443` and we point net/http at
// that vsock socket. TLS is negotiated end-to-end inside the enclave.
package llm

import (
	"fmt"
	"net/http"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/vsockhttp"
)

func newOpenRouterHTTPClient(boot *qtypes.BootstrapData) *http.Client {
	tunnels := []vsockhttp.Tunnel{
		{
			Host: openRouterHost,
			CID:  parseProxyCID(boot.OpenRouterVsockProxy),
			Port: parseProxyPort(boot.OpenRouterVsockProxy),
		},
	}
	c := vsockhttp.NewClient(tunnels)
	c.Timeout = 10 * time.Minute // long-running streams
	return c
}

// parseProxyCID / parseProxyPort split a "<cid>:<port>" string. Defaults
// (3, 8004) match the OpenRouter vsock-proxy port the parent's user-data
// installs.
func parseProxyCID(s string) uint32 {
	cid, _ := splitCIDPort(s, 3, 8004)
	return cid
}

func parseProxyPort(s string) uint32 {
	_, port := splitCIDPort(s, 3, 8004)
	return port
}

func splitCIDPort(s string, defaultCID, defaultPort uint32) (uint32, uint32) {
	if s == "" {
		return defaultCID, defaultPort
	}
	var cid, port uint32
	if _, err := fmt.Sscanf(s, "%d:%d", &cid, &port); err != nil {
		return defaultCID, defaultPort
	}
	return cid, port
}
