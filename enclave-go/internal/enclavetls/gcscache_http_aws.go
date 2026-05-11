//go:build cloud_aws

// vsock-tunneled HTTP client for the GCS-backed autocert cache on the
// AWS-side enclave.
//
// AWS Nitro Enclaves have no network interface. Outbound HTTPS must
// travel via vsock to the parent EC2 host's vsock-proxy daemon, which
// terminates the TCP from the enclave and forwards to the real
// upstream. TLS stays end-to-end between the enclave and the
// upstream API.
//
// gcscache needs two hosts:
//   - oauth2.googleapis.com   — JWT exchange for the SA-key access token
//   - storage.googleapis.com  — the cert read/write
//
// These ports MUST match the parent's /etc/nitro_enclaves/vsock-proxy.yaml
// (configured by tools/deploy-aws-nitro.sh user-data). 8030 is shared
// with the LLM-side oauth2 tunnel in http_client_aws.go; 8034 is the
// new storage-API tunnel.
package enclavetls

import (
	"net/http"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/vsockhttp"
)

var gcsCacheTunnels = []vsockhttp.Tunnel{
	{Host: "oauth2.googleapis.com", CID: 3, Port: 8030},
	{Host: "storage.googleapis.com", CID: 3, Port: 8034},
}

func newCacheHTTPClient() *http.Client {
	c := vsockhttp.NewClient(gcsCacheTunnels)
	c.Timeout = 30 * time.Second
	return c
}

func newTokenHTTPClient() *http.Client {
	c := vsockhttp.NewClient(gcsCacheTunnels)
	c.Timeout = 10 * time.Second
	return c
}
