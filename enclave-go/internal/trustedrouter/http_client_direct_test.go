//go:build !cloud_aws

package trustedrouter

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestControlPlaneHTTPClientPoolsAndResumesTLS(t *testing.T) {
	client := newControlPlaneHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = false")
	}
	if transport.MaxIdleConns < 256 || transport.MaxIdleConnsPerHost < 128 {
		t.Fatalf(
			"idle pool = %d/%d, want at least 256/128",
			transport.MaxIdleConns,
			transport.MaxIdleConnsPerHost,
		)
	}
	if transport.MaxConnsPerHost < transport.MaxIdleConnsPerHost {
		t.Fatalf("MaxConnsPerHost = %d, below idle-per-host %d", transport.MaxConnsPerHost, transport.MaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout < 60*time.Second {
		t.Fatalf("IdleConnTimeout = %s, want >= 60s", transport.IdleConnTimeout)
	}
	if transport.ResponseHeaderTimeout <= 0 || transport.ResponseHeaderTimeout >= client.Timeout {
		t.Fatalf("ResponseHeaderTimeout = %s, client timeout = %s", transport.ResponseHeaderTimeout, client.Timeout)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %d", transport.TLSClientConfig.MinVersion)
	}
	if transport.TLSClientConfig.ClientSessionCache == nil {
		t.Fatal("TLS session cache is disabled")
	}
}
