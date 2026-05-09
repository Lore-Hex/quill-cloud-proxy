//go:build !linux

// Stub for non-Linux builds (local dev on macOS). The real
// implementation lives in peercred_linux.go and uses SO_PEERCRED.
//
// On non-Linux builds peerPID returns 0 + a "not implemented" error;
// the unix dialer in tinfoil_attest.go treats that as a soft skip
// (PID enforcement only activates inside Confidential Space, which is
// Linux). Local-dev tinfoil flow runs without it — there's no
// adversary on a developer laptop.
package llm

import (
	"errors"
	"net"
)

func peerPID(c net.Conn) (int, error) {
	return 0, errors.New("peercred: SO_PEERCRED only supported on Linux")
}
