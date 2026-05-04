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
	"context"
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
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Server holds the freshly-minted cert + the tls.Config the listener wraps.
type Server struct {
	Certificate     tls.Certificate
	LeafFingerprint string // SHA-256 of DER, lowercase hex
	tlsConfig       *tls.Config
	mu              sync.RWMutex
	leafDER         []byte
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

	srv := &Server{
		Certificate: cert,
		tlsConfig: &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			NextProtos:               []string{"http/1.1"},
			PreferServerCipherSuites: true,
		},
	}
	srv.setLeafDER(der)
	return srv, nil
}

// NewACME configures a TLS listener that obtains a public certificate inside
// the enclave using TLS-ALPN-01 on port 443. By default, ACME account and
// certificate private keys stay in process memory; cacheDir may be set when
// the deployment has a sealed enclave-local cache. If gcsCacheBucket is
// non-empty, the cache is backed by GCS instead — required for multi-replica
// MIGs since LE's TLS-ALPN-01 validation can land on any backend the L4 LB
// chose, and only a shared cache lets every replica answer with the same
// challenge token.
func NewACME(dnsName, email, cacheDir, directoryURL, gcsCacheBucket string) (*Server, error) {
	var cache autocert.Cache = newMemoryACMECache()
	switch {
	case gcsCacheBucket != "":
		cache = NewGCSCache(gcsCacheBucket)
	case cacheDir != "" && cacheDir != "memory":
		if err := os.MkdirAll(cacheDir, 0o700); err != nil {
			return nil, fmt.Errorf("enclavetls: create acme cache: %w", err)
		}
		cache = autocert.DirCache(cacheDir)
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(dnsName),
		Cache:      cache,
		Email:      email,
	}
	if directoryURL != "" {
		manager.Client = &acme.Client{DirectoryURL: directoryURL}
	}

	srv := &Server{}
	tlsConfig := manager.TLSConfig()
	managerGetCertificate := tlsConfig.GetCertificate
	tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := managerGetCertificate(hello)
		if err != nil {
			// Operationally critical: without this line autocert failures
			// surface only as TLS alert 80 to the client; the enclave logs
			// nothing. SNI is not prompt content (it's the public hostname
			// the client requested) so logging it doesn't violate the
			// no-prompt-logging policy.
			fmt.Fprintf(os.Stderr, "enclavetls.acme_get_certificate_failed sni=%q err=%v\n", hello.ServerName, err)
		}
		if err == nil && cert != nil && len(cert.Certificate) > 0 && !supportsProto(hello.SupportedProtos, acme.ALPNProto) {
			srv.setLeafDER(cert.Certificate[0])
		}
		return cert, err
	}
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.NextProtos = []string{"http/1.1", acme.ALPNProto}
	srv.tlsConfig = tlsConfig
	return srv, nil
}

// Wrap turns a plaintext listener (e.g. vsock) into one whose accepted
// connections are TLS-terminated. The handshake happens lazily on first
// read/write; callers should set their own deadlines.
func (s *Server) Wrap(inner net.Listener) net.Listener {
	return tls.NewListener(inner, s.tlsConfig)
}

func (s *Server) CurrentLeafDER() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.leafDER) == 0 {
		return nil
	}
	out := make([]byte, len(s.leafDER))
	copy(out, s.leafDER)
	return out
}

func (s *Server) CurrentFingerprint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LeafFingerprint
}

func (s *Server) setLeafDER(der []byte) {
	fp := sha256.Sum256(der)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leafDER = append(s.leafDER[:0], der...)
	s.LeafFingerprint = hex.EncodeToString(fp[:])
}

func supportsProto(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

type memoryACMECache struct {
	mu    sync.RWMutex
	items map[string][]byte
}

func newMemoryACMECache() *memoryACMECache {
	return &memoryACMECache{items: make(map[string][]byte)}
}

func (c *memoryACMECache) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, ok := c.items[key]
	if !ok {
		return nil, autocert.ErrCacheMiss
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func (c *memoryACMECache) Put(_ context.Context, key string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = append([]byte(nil), data...)
	return nil
}

func (c *memoryACMECache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
	return nil
}
