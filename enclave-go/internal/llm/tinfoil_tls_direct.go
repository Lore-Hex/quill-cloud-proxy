//go:build !cloud_aws

package llm

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

func dialTinfoilTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
	}
	return dialer.DialContext(ctx, network, addr)
}
