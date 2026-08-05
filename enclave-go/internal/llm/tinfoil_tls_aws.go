//go:build cloud_aws

package llm

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
)

// dialTinfoilTLS keeps TLS termination and fingerprint verification inside
// Nitro. The parent vsock proxy receives only encrypted TLS records.
func dialTinfoilTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	httpc := defaultHTTPClient()
	transport, ok := httpc.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil {
		return nil, errors.New("tinfoil: AWS vsock transport unavailable")
	}
	rawConn, err := transport.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = rawConn.Close()
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
