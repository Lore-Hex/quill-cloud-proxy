//go:build !cloud_aws

// Default control-plane HTTP client. Plain net.Dialer-backed.
//
// The cloud_aws variant lives in http_client_aws.go and tunnels via
// vsock to the parent because Nitro Enclaves have no network.

package trustedrouter

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

func newControlPlaneHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 128,
			MaxConnsPerHost:     256,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
			// Authorization may legitimately spend most of its bounded 20s
			// Spanner budget. Keep this below the client's 30s total timeout so
			// the enclave can still return a classified control-plane error.
			ResponseHeaderTimeout: 25 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				ClientSessionCache: tls.NewLRUClientSessionCache(256),
			},
		},
	}
}
