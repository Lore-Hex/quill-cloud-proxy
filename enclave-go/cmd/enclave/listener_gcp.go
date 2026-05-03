//go:build cloud_gcp

// GCP Confidential Space listener: ordinary TCP. The Google L4 GLB
// terminates nothing (TCP passthrough on :443) and forwards the bytes
// to this port; TLS is negotiated end-to-end inside the attested
// workload — same property the AWS path has, just without the vsock
// gymnastics because CSP VMs have direct network identity.
package main

import (
	"net"
)

// EnclaveListenPort is the public TCP port. TLS terminates inside the
// workload, so the GCP network path must pass raw TCP through to this port.
const EnclaveListenPort uint32 = 443

func newRawListener() (net.Listener, error) {
	return net.Listen("tcp", ":443") // #nosec G102 -- public prompt endpoint must bind all interfaces in CSP.
}
