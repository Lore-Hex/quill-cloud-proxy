//go:build cloud_aws

// Outbound verification traffic for the attestation sidecar, over vsock.
//
// WHY THIS FILE EXISTS
//
// A Nitro enclave has no network interface and no resolver. Any outbound
// dial resolves against nothing and fails with:
//
//	dial tcp: lookup api-github-proxy.tinfoil.sh on [::1]:53:
//	          connect: cannot assign requested address
//
// which is what killed this sidecar — and with it the whole enclave — until
// 2026-07-31. Everything leaving the enclave must instead go over vsock to
// the parent, which runs a vsock-proxy per host that terminates the TCP dial
// on the outside.
//
// The main enclave binary already solves this with internal/vsockhttp, but
// the sidecar is a SEPARATE Go module and that package lives under
// internal/, so it cannot be imported across the module boundary. This is a
// deliberately minimal re-implementation rather than a refactor of the
// working main-binary path.
//
// TLS is unaffected: the proxy is a byte pipe, so the handshake is still
// end-to-end between this process and the upstream host. The parent never
// sees plaintext, which is the property the whole enclave exists to provide.
//
// FAIL CLOSED. A host that is not in the table below returns an error rather
// than falling through to a normal DNS dial. A silent fallback would look
// like it worked right up until it was asked to attest something.
//
// THE TABLE MUST STAY IN LOCKSTEP with the parent side in
// tools/deploy-aws-nitro.sh — both the vsock-proxy.yaml allowlist and the
// write_vsock_unit lines. Adding a host is a one-line edit in each of the
// three places; missing one produces exactly the DNS error above.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
	tinfoilclient "github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// parentCID is the well-known vsock context ID of the parent instance.
const parentCID = 3

// vsockTunnels maps hostname -> the parent's vsock-proxy port for that host.
//
// These are the sidecar's VERIFICATION path. Note that inference.tinfoil.sh
// (port 8017) is the DATA path used by the main binary; the two are separate
// and the sidecar needs its own routes even though the host is similar.
var vsockTunnels = map[string]uint32{
	"api-github-proxy.tinfoil.sh": 8042, // tinfoil release digest lookup
	"tuf-repo-cdn.sigstore.dev":   8043, // sigstore TUF root of trust
	"rekor.sigstore.dev":          8044, // transparency-log inclusion proof
	// Already proxied on 8017 for the MAIN binary's data path; the sidecar
	// needs the same host for verifyEnclave, so it reuses that port rather
	// than opening a second one.
	"inference.tinfoil.sh":            8017, // enclave measurements (.well-known)
	"gh-attestation-proxy.tinfoil.sh": 8045,
	// AMD Key Distribution Service proxy: the VCEK endorsement certificate
	// that roots the SEV-SNP report. Terminal step of the verify chain.
	"kds-proxy.tinfoil.sh": 8046, // GitHub attestation bundle for the code digest
	// Chutes' signed TDX quote is verified with Intel collateral, and its
	// signed GPU evidence is submitted to NVIDIA Remote Attestation Service.
	// Both are verification-only paths; no prompt or response bytes use them.
	"api.trustedservices.intel.com": 8051,
	"nras.attestation.nvidia.com":   8052,
}

// unconfiguredHostError is returned instead of attempting a DNS dial, so a
// missing route is loud rather than mysterious.
type unconfiguredHostError struct{ host string }

func (e *unconfiguredHostError) Error() string {
	return fmt.Sprintf(
		"sidecar: no vsock route for %q — add it to vsockTunnels in "+
			"vsock_transport.go AND to both the vsock-proxy allowlist and the "+
			"write_vsock_unit lines in tools/deploy-aws-nitro.sh",
		e.host,
	)
}

// dialVsock routes addr to the parent's byte-pipe proxy. It never falls back
// to the enclave's host network, including when addr is malformed or unrouted.
func dialVsock(addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	port, ok := vsockTunnels[host]
	if !ok {
		return nil, &unconfiguredHostError{host: host}
	}
	return vsock.Dial(parentCID, port, nil)
}

// dialTLSOverVsock preserves tls.Dial's TLS configuration semantics while
// replacing only its underlying network dial. TLS remains end-to-end: the
// parent receives encrypted bytes, and the handshake and certificate checks
// happen in this process before the connection is returned to the verifier.
func dialTLSOverVsock(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("sidecar: unsupported TLS network %q", network)
	}

	rawConn, err := dialVsock(addr)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = &tls.Config{}
	}
	if cfg.ServerName == "" {
		// Match crypto/tls.Dial: clone before inferring ServerName so the
		// caller's configuration is not mutated.
		cfg = cfg.Clone()
		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}
		cfg.ServerName = addr[:colonPos]
	}

	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// newVsockTransport returns an http.Transport that dials every request over
// vsock to the parent proxy for that host.
func newVsockTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			return dialVsock(addr)
		},
		// The enclave has one hop to a local proxy, so these are generous
		// enough for a slow upstream without letting a hung dial wedge the
		// verify loop forever.
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
	}
}

// installPlatformTransport makes vsock the process-wide default for the
// cloud_aws build. The GCP build has a normal network interface and uses the
// direct implementation in direct_transport.go.
//
// HTTP requests use the process-wide default transport. The verifier's final
// certificate-binding check uses a raw TLS dial, so its vendored dial hook is
// installed separately. Both paths fail closed through the same route table.
func installPlatformTransport() string {
	transport := newVsockTransport()
	http.DefaultTransport = transport
	http.DefaultClient = &http.Client{Transport: transport, Timeout: 60 * time.Second}
	tinfoilclient.DialTLSContext = dialTLSOverVsock
	return "vsock"
}
