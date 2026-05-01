//go:build cloud_aws

// AWS Nitro listener: bind vsock CID-LOCAL on the well-known port the
// parent's TCP pump forwards to. The parent runs the listener loop on
// the host network (TCP :8444) and tunnels accepted bytes into here.
package main

import (
	"net"

	"github.com/mdlayher/vsock"
)

// EnclaveListenPort is the vsock port the parent's relay forwards to.
const EnclaveListenPort uint32 = 8001

func newRawListener() (net.Listener, error) {
	return vsock.Listen(EnclaveListenPort, nil)
}
