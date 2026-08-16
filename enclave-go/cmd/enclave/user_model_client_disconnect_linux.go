//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// userModelClientDisconnect watches the peer socket without consuming bytes.
// Buffered callers cannot receive SSE keepalives, so a write-only disconnect
// signal is the only way to cancel an owner request before its budget expires.
// MSG_PEEK preserves a pipelined next request on the enclave's keep-alive
// connection; POLLRDHUP supplies the actual cancellation signal.
func userModelClientDisconnect(ctx context.Context, writer io.Writer) <-chan struct{} {
	conn, ok := userModelSyscallConn(writer)
	if !ok {
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil
	}
	fd := -1
	var duplicateErr error
	if err := raw.Control(func(rawFD uintptr) {
		fd, duplicateErr = unix.Dup(int(rawFD))
	}); err != nil || duplicateErr != nil || fd < 0 {
		return nil
	}

	disconnected := make(chan struct{})
	go func() {
		defer unix.Close(fd)
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP | unix.POLLRDHUP}}
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			count, pollErr := unix.Poll(poll, 250)
			if pollErr != nil {
				if pollErr == unix.EINTR {
					continue
				}
				return
			}
			if count == 0 {
				continue
			}
			events := poll[0].Revents
			if events&(unix.POLLERR|unix.POLLHUP|unix.POLLRDHUP) != 0 {
				close(disconnected)
				return
			}
			if events&unix.POLLIN != 0 {
				var peek [1]byte
				n, _, recvErr := unix.Recvfrom(fd, peek[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
				if recvErr == nil && n == 0 {
					close(disconnected)
					return
				}
				// Readable encrypted/pipelined bytes belong to the next HTTP
				// request. Do not consume them or spin on the readable fd.
				time.Sleep(25 * time.Millisecond)
			}
		}
	}()
	return disconnected
}

func userModelSyscallConn(writer io.Writer) (syscall.Conn, bool) {
	current := writer
	for range 8 {
		switch conn := current.(type) {
		case syscall.Conn:
			return conn, true
		case *responseStatsConn:
			current = conn.Conn
		case *tls.Conn:
			current = conn.NetConn()
		case interface{ NetConn() net.Conn }:
			current = conn.NetConn()
		default:
			return nil, false
		}
	}
	return nil, false
}
