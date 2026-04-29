// Package enclavetls generates the TLS server certificate the enclave
// presents to inbound connections, and wraps a net.Listener so that every
// accepted connection is TLS-terminated inside the enclave.
//
// Why this exists: the V1 chain terminates TLS at the ALB, which means
// AWS infrastructure (and, for ~milliseconds in transit, the parent
// process) sees prompt content in plaintext. Phase 1 of "TLS-inside" puts
// the TLS endpoint inside the attested binary so the byte stream from the
// client is opaque until it reaches code measured by PCR0.
//
// Cert provisioning: the cert is generated freshly at enclave startup
// using crypto/rand for the private key. The key never touches disk and
// never leaves the enclave's memory. The price is that the cert rotates
// on every enclave restart — clients can't statically pin a hash. Phase 3
// will surface the current fingerprint via an attestation endpoint so
// clients can fetch + verify before trusting the prompt path.
//
// For the Phase 1 smoke test we expose the cert via a startup log line
// (and the parent's bootstrap-RPC response so the smoke harness can pin
// it for the lifetime of one boot).
package enclavetls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"time"
)

// Server holds the freshly-minted cert + the tls.Config the listener wraps.
type Server struct {
	Certificate     tls.Certificate
	LeafFingerprint string // SHA-256 of DER, lowercase hex
	tlsConfig       *tls.Config
}

// NewSelfSigned generates an ECDSA P-256 keypair + a self-signed cert with
// `dnsName` as the only Subject Alternative Name. The cert is valid for one
// year — well within Nitro instance lifetimes; clients shouldn't be pinning
// long-lived certs anyway since each enclave boot rotates.
func NewSelfSigned(dnsName string) (*Server, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enclavetls: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("enclavetls: serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   dnsName,
			Organization: []string{"Quill Cloud (attested enclave)"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{dnsName},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("enclavetls: sign: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        nil, // populated below
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("enclavetls: parse own cert: %w", err)
	}
	cert.Leaf = leaf

	fp := sha256.Sum256(der)

	return &Server{
		Certificate:     cert,
		LeafFingerprint: hex.EncodeToString(fp[:]),
		tlsConfig: &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			NextProtos:               []string{"http/1.1"},
			PreferServerCipherSuites: true,
		},
	}, nil
}

// Wrap turns a plaintext listener (e.g. vsock) into one whose accepted
// connections are TLS-terminated. The handshake happens lazily on first
// read/write; callers should set their own deadlines.
func (s *Server) Wrap(inner net.Listener) net.Listener {
	return tls.NewListener(inner, s.tlsConfig)
}
