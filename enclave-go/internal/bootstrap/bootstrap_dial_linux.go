//go:build cloud_aws && linux

package bootstrap

import (
	"context"
	"errors"
	"net"

	"github.com/mdlayher/socket"
	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

type bootstrapConn struct {
	*socket.Conn
	local, remote net.Addr
}

func (c *bootstrapConn) LocalAddr() net.Addr  { return c.local }
func (c *bootstrapConn) RemoteAddr() net.Addr { return c.remote }

// The existing vsock.Dial uses context.Background for connect. Use its same
// socket implementation with the boot context so a stalled parent cannot
// extend the complete boot budget or leak a background dial goroutine.
func dialBootstrap(ctx context.Context, port uint32) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := socket.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0, "bootstrap-vsock", nil)
	if err != nil {
		return nil, err
	}
	remote := &unix.SockaddrVM{CID: ParentCID, Port: port}
	if _, err := conn.Connect(ctx, remote); err != nil {
		_ = conn.Close()
		return nil, err
	}
	address, err := conn.Getsockname()
	local, ok := address.(*unix.SockaddrVM)
	if err != nil || !ok {
		_ = conn.Close()
		return nil, errors.New("bootstrap: invalid local vsock address")
	}
	return &bootstrapConn{Conn: conn,
		local:  &vsock.Addr{ContextID: local.CID, Port: local.Port},
		remote: &vsock.Addr{ContextID: ParentCID, Port: port},
	}, nil
}
