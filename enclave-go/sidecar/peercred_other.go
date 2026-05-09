//go:build !linux

// Stub for non-Linux builds (local dev on macOS). The real
// implementation lives in peercred_linux.go and uses SO_PEERCRED.
//
// On non-Linux builds peerUID always returns 0 and a "not implemented"
// error; the caller (uidEnforcingListener.Accept) treats that as a
// soft skip — UID enforcement only activates inside the Confidential
// Space VM (which is Linux). Local-dev sidecar runs without it, which
// is fine: there's no adversary on a developer laptop.
package main

import (
	"errors"
	"net"
)

func peerUID(c net.Conn) (int, error) {
	return 0, errors.New("peercred: SO_PEERCRED only supported on Linux")
}
