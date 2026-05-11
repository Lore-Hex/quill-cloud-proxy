//go:build !cloud_aws

// Default control-plane HTTP client. Plain net.Dialer-backed.
//
// The cloud_aws variant lives in http_client_aws.go and tunnels via
// vsock to the parent because Nitro Enclaves have no network.

package trustedrouter

import (
	"net/http"
	"time"
)

func newControlPlaneHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
