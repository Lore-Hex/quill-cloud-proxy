//go:build cloud_gcp

// GCP listener: ordinary TCP, port determined by deployment shape.
//
// Two supported deployment targets, selected by the $PORT env var:
//
//  1. Confidential Space VM ($PORT unset): bind :443. The Google L4 GLB
//     terminates nothing (TCP passthrough) and forwards the bytes to this
//     port; TLS is negotiated end-to-end inside the attested workload —
//     same property the AWS path has, just without the vsock gymnastics
//     because CSP VMs have direct network identity.
//
//  2. Cloud Run with Confidential VM ($PORT=8080 typically): bind
//     :$PORT and speak HTTP. Cloud Run's edge load balancer terminates
//     TLS at GCP's edge and forwards plaintext over Google's internal
//     fabric to this container. Trust property is weaker (Google's
//     fabric sees plaintext between edge and enclave), but the workload
//     still doesn't log and the image digest is still attested. Used
//     for low-traffic regions where the cost of running a VM 24/7
//     isn't justified.
//
// In both modes, the *enclave-attested-tls* layer is feature-flagged by
// QUILL_ENCLAVE_TLS=true. Cloud Run mode leaves it unset because Cloud
// Run won't deliver pass-through TLS to the container.
package main

import (
	"net"
	"os"
)

// EnclaveListenPort is the public TCP port. TLS terminates inside the
// workload (CSP-VM target) or at GCP's edge (Cloud Run target).
const EnclaveListenPort uint32 = 443

func newRawListener() (net.Listener, error) {
	addr := ":443"
	if port := os.Getenv("PORT"); port != "" {
		// Cloud Run injects PORT=8080. Honor it so the same binary
		// works in both deployment shapes without a build-tag fork.
		addr = ":" + port
	}
	return net.Listen("tcp", addr) // #nosec G102 -- public prompt endpoint must bind all interfaces.
}
