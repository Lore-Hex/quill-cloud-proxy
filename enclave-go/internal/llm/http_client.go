package llm

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamcert"
)

const defaultStreamingHTTPTimeout = 10 * time.Minute

func pooledHTTPClient(timeout time.Duration) *http.Client {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	registry := &upstreamcert.Registry{}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           providerDialContext,
		DialTLSContext:        registry.DialTLSContext(providerDialContext, tlsConfig, 10*time.Second),
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return lockProviderHTTPClient(&http.Client{
		Timeout:   timeout,
		Transport: &upstreamcert.Transport{Base: transport, Registry: registry},
	})
}
