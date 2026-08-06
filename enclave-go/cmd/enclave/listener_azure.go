//go:build cloud_azure

// Azure confidential-container listener: ordinary TCP, same as the GCP
// Confidential Space path and for the same reason. An ACI container group has
// its own network identity and the ingress in front of it passes TCP through
// on :443, so TLS is negotiated end-to-end inside the attested container. No
// vsock gymnastics — that indirection exists only because a Nitro enclave has
// no network at all.
package main

import (
	"net"
)

// EnclaveListenPort is the public TCP port. TLS terminates inside the attested
// container, so the Azure network path must pass raw TCP through to this port
// rather than terminating it at an application gateway.
const EnclaveListenPort uint32 = 443

func newRawListener() (net.Listener, error) {
	return net.Listen("tcp", ":443") // #nosec G102 -- public prompt endpoint must bind all interfaces in the container group.
}
