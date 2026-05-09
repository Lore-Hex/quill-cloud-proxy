//go:build linux

package llm

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// peerPID returns the PID of the process on the other end of a Unix
// socket connection, via SO_PEERCRED. Used by the tinfoil_attest.go
// dialer to verify the connected sidecar is actually the child the
// main enclave fork-exec'd at startup, not some other process that
// raced us to bind @tinfoil-attest.
//
// Linux-only because SO_PEERCRED is a Linux feature; sibling stub in
// peercred_other.go covers macOS so the package builds on dev hosts.
func peerPID(c net.Conn) (int, error) {
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
	return int(cred.Pid), nil
}
