//go:build cloud_aws

package llm

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/vsockhttp"
)

// dialTinfoilTLS keeps TLS termination and fingerprint verification inside
// Nitro. The parent vsock proxy receives only encrypted TLS records.
func dialTinfoilTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != tinfoilEnclaveHost || port != "443" {
		return nil, errProviderEgress
	}
	transport := vsockhttp.NewTransport(awsProviderTunnels)
	rawConn, err := transport.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}
