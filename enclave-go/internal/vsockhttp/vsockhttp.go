//go:build cloud_aws

// Package vsockhttp wires net/http (and therefore aws-sdk-go-v2) to talk
// to AWS endpoints over a vsock tunnel.
//
// The parent runs `vsock-proxy` listening on (CID 3, port N) and forwarding
// raw bytes to e.g. bedrock-runtime.us-east-1.amazonaws.com:443. The enclave
// uses this transport: when aws-sdk dials bedrock-runtime.us-east-1.amazonaws.com,
// our DialContext substitutes a vsock connection to (3, N) instead. TLS is
// then negotiated end-to-end between the enclave and AWS — the parent only
// pumps encrypted bytes.
package vsockhttp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
)

// Tunnel maps an AWS hostname to the parent's vsock-proxy port.
type Tunnel struct {
	Host string // e.g. "bedrock-runtime.us-east-1.amazonaws.com"
	CID  uint32 // typically 3 (the parent host)
	Port uint32 // vsock-proxy listening port
}

// NewTransport returns an http.Transport whose DialContext routes the
// configured hostnames over vsock instead of TCP. Anything not in the list
// fails closed (we want only the AWS endpoints to be reachable).
func NewTransport(tunnels []Tunnel) *http.Transport {
	hostMap := make(map[string]Tunnel, len(tunnels))
	for _, t := range tunnels {
		hostMap[strings.ToLower(t.Host)] = t
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			t, ok := hostMap[strings.ToLower(host)]
			if !ok {
				return nil, &UnconfiguredHostError{Host: host}
			}
			return vsock.Dial(t.CID, t.Port, nil)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
}

// NewClient returns an http.Client wrapping the vsock transport.
func NewClient(tunnels []Tunnel) *http.Client {
	return &http.Client{
		Transport: NewTransport(tunnels),
		Timeout:   600 * time.Second, // Bedrock streams can be long
	}
}

// UnconfiguredHostError is returned when AWS SDK attempts to connect to a
// hostname we haven't allowlisted in the vsock tunnel map.
type UnconfiguredHostError struct {
	Host string
}

func (e *UnconfiguredHostError) Error() string {
	return "vsockhttp: host not in tunnel allowlist: " + e.Host
}
