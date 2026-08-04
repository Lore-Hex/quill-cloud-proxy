package client

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

// DialTLSContext lets an embedder route this dial somewhere other than the
// host network. Defaults to the original tls.Dial, so behavior is unchanged
// unless explicitly overridden.
var DialTLSContext = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
	return tls.Dial(network, addr, cfg)
}

// enclaveValidPubKey checks if the public key covered by the attestation matches the public key of the enclave
func enclaveValidPubKey(enclave string, enclaveVerification *attestation.Verification) error {
	// Get cert from TLS connection
	var addr string
	if strings.Contains(enclave, ":") {
		// Enclave already has a port specified
		addr = enclave
	} else {
		// Append default HTTPS port
		addr = enclave + ":443"
	}

	conn, err := DialTLSContext("tcp", addr, &tls.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to enclave: %v", err)
	}
	defer conn.Close()
	certFP, err := attestation.ConnectionCertFP(conn.ConnectionState())
	if err != nil {
		return fmt.Errorf("failed to get certificate fingerprint: %v", err)
	}

	// Check if the certificate fingerprint matches the one in the verification
	if certFP != enclaveVerification.TLSPublicKeyFP {
		return fmt.Errorf("certificate fingerprint mismatch: expected %s, got %s", enclaveVerification.TLSPublicKeyFP, certFP)
	}

	return nil
}
