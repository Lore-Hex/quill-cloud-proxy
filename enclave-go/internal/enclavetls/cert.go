// Package enclavetls generates the TLS server certificate the enclave
// presents to inbound connections, and wraps a net.Listener so that every
// accepted connection is TLS-terminated inside the enclave.
//
// Why this exists: production prompt traffic must never terminate TLS in
// the parent process or a load balancer. The TLS endpoint lives inside the
// attested binary, so the byte stream from the client is opaque until it
// reaches code measured by PCR0.
//
// Cert provisioning: the cert is generated freshly at enclave startup
// using crypto/rand for the private key. The key never touches disk and
// never leaves the enclave's memory. The public-certificate path uses ACME
// inside the enclave so normal SDK clients can validate TLS while the
// private key remains enclave-local.
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
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	ExporterLabel  = "EXPORTER-Channel-Binding"
	ExporterLength = 32
)

// Server holds the freshly-minted cert + the tls.Config the listener wraps.
type Server struct {
	Certificate     tls.Certificate
	LeafFingerprint string // SHA-256 of DER, lowercase hex
	tlsConfig       *tls.Config
	mu              sync.RWMutex
	leafDER         []byte

	// singleCert is true when this Server serves exactly ONE certificate for
	// every connection, i.e. the self-signed path, where that cert carries all
	// SANs. Only then may Accept() pre-seed a connection's leaf from the
	// process-global leafDER, because with one cert the global and the
	// per-connection value cannot disagree.
	//
	// On the ACME path they CAN disagree, and did: autocert issues one cert
	// PER SNI NAME, GetCertificate writes both the per-connection leaf and the
	// global, and Go's TLS 1.3 server never calls GetCertificate on a resumed
	// (PSK) handshake. So a resumed session kept the pre-seed — whichever
	// hostname most recently completed a FULL handshake anywhere in the
	// process — and /attestation bound a certificate the client never saw.
	// Reproduced live on three GCP replicas serving five hostnames.
	singleCert bool
}

type selectedLeafSetter interface {
	setSelectedLeafDER([]byte)
}

type selectedLeafReader interface {
	SelectedLeafDER() []byte
}

type selectedExporterReader interface {
	SelectedExporter() ([]byte, error)
}

type tlsConnectionStateReader interface {
	ConnectionState() tls.ConnectionState
}

type selectedLeafConn struct {
	net.Conn
	mu      sync.RWMutex
	leafDER []byte
}

// NetConn exposes the transport socket to infrastructure that must observe
// connection state without consuming TLS bytes. In particular, the Linux
// user-model disconnect watcher needs the TCP fd to cancel paid owner work
// when a buffered caller has already gone away.
func (c *selectedLeafConn) NetConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.Conn
}

func (c *selectedLeafConn) setSelectedLeafDER(der []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leafDER = append(c.leafDER[:0], der...)
}

func (c *selectedLeafConn) SelectedLeafDER() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.leafDER) == 0 {
		return nil
	}
	out := make([]byte, len(c.leafDER))
	copy(out, c.leafDER)
	return out
}

type trackedTLSConn struct {
	*tls.Conn
	selected *selectedLeafConn
}

func (c *trackedTLSConn) SelectedLeafDER() []byte {
	if c == nil || c.selected == nil {
		return nil
	}
	return c.selected.SelectedLeafDER()
}

type trackingListener struct {
	net.Listener
	server *Server
}

// NewSelfSigned generates an ECDSA P-256 keypair + a self-signed cert with
// `dnsName` as Subject Alternative Name. dnsName may be a comma-separated
// list when one regional gateway must serve both canonical and regional SNI.
// The cert is valid for one
// year — well within Nitro instance lifetimes; clients shouldn't be pinning
// long-lived certs anyway since each enclave boot rotates.
func NewSelfSigned(dnsName string) (*Server, error) {
	dnsNames := splitDNSNames(dnsName)
	if len(dnsNames) == 0 {
		return nil, fmt.Errorf("enclavetls: dns name required")
	}

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
			CommonName:   dnsNames[0],
			Organization: []string{"Quill Cloud (attested enclave)"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
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
		// One cert with every SAN, installed via Certificates rather than
		// GetCertificate — which is never called on this path at all, making
		// Accept()'s pre-seed the ONLY writer of the per-connection leaf.
		// Removing that pre-seed would leave SelectedLeafDER nil on every AWS
		// Nitro connection and 503 the whole fleet's /attestation.
		singleCert:  true,
		Certificate: cert,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			// G6/RFC 9266 closure depends on TLS 1.3 exporter channel binding:
			// every supported SDK and modern tool negotiates 1.3, and TLS 1.2
			// exporters are EMS-dependent.
			MinVersion:               tls.VersionTLS13,
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
func NewACME(
	dnsName, email, cacheDir, directoryURL, gcsCacheBucket string,
	eab *acme.ExternalAccountBinding,
) (*Server, error) {
	dnsNames := splitDNSNames(dnsName)
	if len(dnsNames) == 0 {
		return nil, fmt.Errorf("enclavetls: dns name required")
	}

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
		HostPolicy: autocert.HostWhitelist(dnsNames...),
		Cache:      cache,
		Email:      email,
		// Required by every CA worth failing over to (Google Trust Services,
		// ZeroSSL, commercial ACME). nil for Let's Encrypt, which does not use
		// it — so this is inert until a second CA is configured.
		ExternalAccountBinding: eab,
	}
	if directoryURL != "" {
		manager.Client = &acme.Client{DirectoryURL: directoryURL}
	}

	srv := &Server{singleCert: false}
	tlsConfig := manager.TLSConfig()
	managerGetCertificate := tlsConfig.GetCertificate
	tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := getCertificateWithECDSAFallback(managerGetCertificate, hello)
		if err != nil {
			// Operationally critical: without this line autocert failures
			// surface only as TLS alert 80 to the client; the enclave logs
			// nothing. SNI is not prompt content (it's the public hostname
			// the client requested) so logging it doesn't violate the
			// no-prompt-logging policy.
			fmt.Fprintf(os.Stderr, "enclavetls.acme_get_certificate_failed sni=%q err=%v\n", hello.ServerName, err)
		}
		if err == nil && cert != nil && len(cert.Certificate) > 0 {
			if setter, ok := hello.Conn.(selectedLeafSetter); ok {
				setter.setSelectedLeafDER(cert.Certificate[0])
			}
			if !supportsProto(hello.SupportedProtos, acme.ALPNProto) {
				srv.setLeafDER(cert.Certificate[0])
			}
		}
		return cert, err
	}
	// G6/RFC 9266 closure depends on TLS 1.3 exporter channel binding:
	// every supported SDK and modern tool negotiates 1.3, and TLS 1.2
	// exporters are EMS-dependent.
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{"http/1.1", acme.ALPNProto}
	// Session resumption is what makes the multi-certificate case unsafe: Go's
	// TLS 1.3 server skips GetCertificate on a PSK handshake, so nothing would
	// record which cert this session actually used. Disabling tickets forces a
	// full handshake per NEW connection — one extra round trip, negligible
	// under keep-alive — and in exchange every connection's attested leaf is
	// the one it was actually served.
	tlsConfig.SessionTicketsDisabled = true
	srv.tlsConfig = tlsConfig
	return srv, nil
}

func splitDNSNames(value string) []string {
	seen := make(map[string]struct{})
	names := make([]string, 0, 1)
	for _, part := range strings.Split(value, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

// Wrap turns a plaintext listener (e.g. vsock) into one whose accepted
// connections are TLS-terminated. The handshake happens lazily on first
// read/write; callers should set their own deadlines.
func (s *Server) Wrap(inner net.Listener) net.Listener {
	return &trackingListener{Listener: inner, server: s}
}

func (l *trackingListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	selected := &selectedLeafConn{Conn: raw}
	// Pre-seed ONLY when the server has a single certificate. On a
	// multi-certificate (ACME) server the global leaf belongs to whichever
	// hostname last completed a full handshake, so seeding it here would
	// attest the wrong certificate on any connection that does not call
	// GetCertificate. See Server.singleCert.
	if l.server != nil && l.server.singleCert {
		if der := l.server.CurrentLeafDER(); len(der) > 0 {
			selected.setSelectedLeafDER(der)
		}
	}
	return &trackedTLSConn{
		Conn:     tls.Server(selected, l.server.tlsConfig),
		selected: selected,
	}, nil
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

func SelectedLeafDER(conn net.Conn) []byte {
	if reader, ok := conn.(selectedLeafReader); ok {
		return reader.SelectedLeafDER()
	}
	return nil
}

func SelectedExporter(conn net.Conn) ([]byte, error) {
	if reader, ok := conn.(selectedExporterReader); ok {
		return reader.SelectedExporter()
	}
	c, ok := conn.(tlsConnectionStateReader)
	if !ok {
		return nil, fmt.Errorf("not a TLS connection")
	}
	state := c.ConnectionState()
	if !state.HandshakeComplete {
		return nil, fmt.Errorf("TLS handshake is not complete")
	}
	if state.Version < tls.VersionTLS13 {
		return nil, fmt.Errorf("exporter channel binding requires TLS 1.3")
	}
	// G6/RFC 9266 closure: derive this from the enclave's own live TLS
	// session. A relay proxy terminates a separate client-facing session with
	// a different master secret, so it cannot present a token bound to this
	// exporter value or mint one itself.
	return state.ExportKeyingMaterial(ExporterLabel, nil, ExporterLength)
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

// getCertificateWithECDSAFallback wraps an autocert GetCertificate with one
// retry that claims P-256 support.
//
// P-256-IN-supported_groups IS NOT "CAN USE AN ECDSA CERT". autocert keys its
// cache by algorithm and decides via supportsECDSA(), which reads the client's
// supported_groups and treats a missing P-256 as "this client needs RSA". It
// then looks up "<host>+rsa", and where no RSA cert was ever issued the
// handshake dies with TLS alert 80 — for a client that would have been
// perfectly happy with the ECDSA leaf the server already serves everyone else.
//
// That heuristic predates TLS 1.3, where the certificate's key type is governed
// by signature_algorithms and NOT by key-exchange groups. This server requires
// 1.3 (it rejects 1.2 outright), so the retry is sound.
//
// It stopped being theoretical: OpenSSL 3.5+ leads with post-quantum/X25519
// groups and can omit P-256 entirely. Reproduced live 2026-08-07 against both
// Azure enclave regions — `openssl s_client -groups X25519` failed while
// `-groups P-256` succeeded, and curl was unaffected, so nothing watching this
// stack noticed. GCP escaped only because an RSA cert happened to be sitting in
// the shared cache from some earlier client.
//
// The retry reaches the SAME cached leaf: it issues nothing, needs no
// rate-limit budget, and cannot invent a certificate that does not exist. If it
// also fails, the ORIGINAL error is returned — the retry must never rewrite the
// diagnosis of an unrelated failure.
func getCertificateWithECDSAFallback(
	get func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	hello *tls.ClientHelloInfo,
) (*tls.Certificate, error) {
	// Steer the lookup BEFORE calling autocert, not after it fails.
	//
	// An earlier version of this retried on error, which was correct in
	// principle and useless in practice: the FIRST call is the expensive one.
	// A cache miss on "<host>+rsa" sends autocert into createCert, which opens
	// an ACME order and BLOCKS on the network — and against a rate-limited CA
	// that block is long enough that the client gives up mid-handshake. The
	// server never even sends a ServerHello. Observed live: the same request
	// that used to fail fast with alert 80 instead hung with no response at
	// all, which is strictly harder to diagnose.
	//
	// So when the client's signature_algorithms say it accepts ECDSA, ask for
	// the ECDSA cert up front. That is a cache HIT, it returns immediately, and
	// no ACME order is ever opened.
	if clientAcceptsECDSA(hello) {
		if ecdsaHello := withP256(hello); ecdsaHello != hello {
			if cert, err := get(ecdsaHello); err == nil {
				return cert, nil
			}
			// Fall through: whatever went wrong was not the algorithm choice,
			// so let the unmodified hello produce the real error.
		}
	}
	return get(hello)
}

// clientAcceptsECDSA reports whether the client's signature_algorithms permit
// an ECDSA leaf.
//
// This is the check autocert's supportsECDSA() should be making on its own for
// TLS 1.3, and the ONLY one that is actually authoritative there: in 1.3 the
// certificate's key type is negotiated through signature_algorithms, while
// supported_groups constrains key exchange. autocert additionally requires
// P-256 among the groups, which is a TLS 1.2-era conflation and is exactly what
// breaks modern OpenSSL clients that lead with X25519.
//
// An empty list means the client stated no preference, which RFC 8446 leaves
// open and autocert also treats as ECDSA-capable.
func clientAcceptsECDSA(hello *tls.ClientHelloInfo) bool {
	if len(hello.SignatureSchemes) == 0 {
		return true
	}
	for _, scheme := range hello.SignatureSchemes {
		switch scheme {
		case tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
			tls.ECDSAWithSHA1:
			return true
		}
	}
	return false
}

// withP256 returns a shallow copy of hello with CurveP256 present in
// SupportedCurves, leaving the caller's struct untouched.
//
// It exists solely to steer autocert's supportsECDSA() heuristic; nothing about
// the actual handshake changes. The copy matters: hello belongs to crypto/tls
// and is reused, so appending in place would corrupt the live handshake state
// for every subsequent lookup on that connection.
func withP256(hello *tls.ClientHelloInfo) *tls.ClientHelloInfo {
	for _, curve := range hello.SupportedCurves {
		if curve == tls.CurveP256 {
			return hello // already advertised; the failure was something else
		}
	}
	clone := *hello
	clone.SupportedCurves = append(append([]tls.CurveID(nil), hello.SupportedCurves...), tls.CurveP256)
	return &clone
}
