//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// peerUID returns the UID of the process on the other end of a Unix
// socket connection, via SO_PEERCRED. Linux-specific; sibling stub in
// peercred_other.go covers macOS / dev hosts so this package stays
// build-clean off-target.
func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("peercred: connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("peercred: SyscallConn: %w", err)
	}
	var cred *syscall.Ucred
	var inner error
	ctlErr := raw.Control(func(fd uintptr) {
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if ctlErr != nil {
		return 0, fmt.Errorf("peercred: Control: %w", ctlErr)
	}
	if inner != nil {
		return 0, fmt.Errorf("peercred: getsockopt: %w", inner)
	}
	return int(cred.Uid), nil
}
