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

// EnclaveListenPort is the TCP port the GLB target group forwards to.
// The container exposes :8001; the VM's iptables rule (set up in the
// CSP container args) translates the GLB's :443 inbound to :8001 here.
const EnclaveListenPort uint32 = 8001

func newRawListener() (net.Listener, error) {
	return net.Listen("tcp", ":8001")
}
