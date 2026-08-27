package enclavetls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sys/unix"
)

// TestNewSelfSigned_ValidCert checks the issued cert is parseable, has the
// expected DNS SAN, and the published fingerprint matches the leaf bytes.
func TestNewSelfSigned_ValidCert(t *testing.T) {
	srv, err := NewSelfSigned("api.quillrouter.com")
	if err != nil {
		t.Fatalf("NewSelfSigned: %v", err)
	}
	if len(srv.Certificate.Certificate) != 1 {
		t.Fatalf("expected 1 cert in chain, got %d", len(srv.Certificate.Certificate))
	}
	if srv.tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", srv.tlsConfig.MinVersion)
	}
	der := srv.Certificate.Certificate[0]

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != "api.quillrouter.com" {
		t.Errorf("CN = %q, want api.quillrouter.com", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "api.quillrouter.com" {
		t.Errorf("DNSNames = %v, want [api.quillrouter.com]", leaf.DNSNames)
	}
	if leaf.IsCA {
		t.Errorf("leaf must not be a CA")
	}
	// Validity: at least 11 months out (we set 365d − 1h).
	want := time.Now().Add(11 * 30 * 24 * time.Hour)
	if leaf.NotAfter.Before(want) {
		t.Errorf("NotAfter = %v, want > %v", leaf.NotAfter, want)
	}

	expFp := sha256.Sum256(der)
	if got := srv.LeafFingerprint; got != hex.EncodeToString(expFp[:]) {
		t.Errorf("LeafFingerprint mismatch: got %s, want %s", got, hex.EncodeToString(expFp[:]))
	}

	gotDER := srv.CurrentLeafDER()
	if !bytes.Equal(gotDER, der) {
		t.Fatal("CurrentLeafDER did not return the active leaf cert")
	}
	gotDER[0] ^= 0xff
	if bytes.Equal(srv.CurrentLeafDER(), gotDER) {
		t.Fatal("CurrentLeafDER returned mutable internal storage")
	}
}

func TestNewSelfSigned_AllowsMultipleDNSNames(t *testing.T) {
	srv, err := NewSelfSigned("api.quillrouter.com, api-us-central1.quillrouter.com,api.quillrouter.com")
	if err != nil {
		t.Fatalf("NewSelfSigned: %v", err)
	}
	leaf, err := x509.ParseCertificate(srv.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != "api.quillrouter.com" {
		t.Errorf("CN = %q, want first configured host", leaf.Subject.CommonName)
	}
	want := []string{"api.quillrouter.com", "api-us-central1.quillrouter.com"}
	if strings.Join(leaf.DNSNames, ",") != strings.Join(want, ",") {
		t.Fatalf("DNSNames = %v, want %v", leaf.DNSNames, want)
	}
}

func TestNewACME_ConfiguresTLSALPNInMemory(t *testing.T) {
	srv, err := NewACME("api.quillrouter.com", "", "", "", "", nil)
	if err != nil {
		t.Fatalf("NewACME: %v", err)
	}
	if srv.tlsConfig == nil {
		t.Fatal("tlsConfig is nil")
	}
	if srv.tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", srv.tlsConfig.MinVersion)
	}
	if !supportsProto(srv.tlsConfig.NextProtos, acme.ALPNProto) {
		t.Fatalf("NextProtos = %v, want ACME TLS-ALPN support", srv.tlsConfig.NextProtos)
	}
	if !supportsProto(srv.tlsConfig.NextProtos, "http/1.1") {
		t.Fatalf("NextProtos = %v, want http/1.1 support", srv.tlsConfig.NextProtos)
	}
	if srv.CurrentLeafDER() != nil {
		t.Fatal("ACME leaf should be empty until the first non-challenge handshake")
	}
}

func TestNewACME_RejectsUnlistedSNIForMultiHostConfig(t *testing.T) {
	srv, err := NewACME("api.quillrouter.com,api-us-central1.quillrouter.com", "", "", "", "", nil)
	if err != nil {
		t.Fatalf("NewACME: %v", err)
	}
	_, err = srv.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "not-api.quillrouter.com"})
	if err == nil {
		t.Fatal("expected unlisted SNI to fail HostPolicy")
	}
}

func TestMemoryACMECacheCopiesValues(t *testing.T) {
	ctx := context.Background()
	cache := newMemoryACMECache()
	if _, err := cache.Get(ctx, "missing"); err != autocert.ErrCacheMiss {
		t.Fatalf("missing cache error = %v, want ErrCacheMiss", err)
	}

	data := []byte("secret")
	if err := cache.Put(ctx, "k", data); err != nil {
		t.Fatalf("Put: %v", err)
	}
	data[0] = 'X'

	got, err := cache.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("cache stored mutable input: %q", got)
	}
	got[0] = 'Y'
	again, err := cache.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get again: %v", err)
	}
	if string(again) != "secret" {
		t.Fatalf("cache returned mutable storage: %q", again)
	}
}

// TestWrap_RoundTrip stands up a TLS-wrapped listener over an in-process
// pipe, connects with a client that pins the server's cert, and verifies the
// handshake completes + bytes round-trip.
func TestWrap_RoundTrip(t *testing.T) {
	srv, err := NewSelfSigned("test.quill.local")
	if err != nil {
		t.Fatal(err)
	}

	// In-memory listener so we don't need real sockets/vsock.
	innerL := newPipeListener(t)
	defer innerL.Close()
	tlsL := srv.Wrap(innerL)

	// Client that explicitly trusts only the server's leaf cert. (We could
	// fetch it via the listener but here we use the same SecCertificate the
	// server holds — same as what /attestation will publish.)
	pool := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(srv.Certificate.Certificate[0])
	pool.AddCert(leaf)
	clientCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "test.quill.local",
		MinVersion: tls.VersionTLS12,
	}

	go func() {
		// One server-side accept + echo one line.
		conn, err := tlsL.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		if n > 0 {
			_, _ = conn.Write(buf[:n])
		}
	}()

	client, err := innerL.dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	tc := tls.Client(client, clientCfg)
	_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	want := "hello-quill"
	if _, err := tc.Write([]byte(want)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(tc, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != want {
		t.Errorf("round-trip = %q, want %q", got, want)
	}
}

func TestWrapTracksSelectedLeafPerConnection(t *testing.T) {
	apiTrusted, err := NewSelfSigned("api.trustedrouter.com")
	if err != nil {
		t.Fatal(err)
	}
	apiQuill, err := NewSelfSigned("api.quillrouter.com")
	if err != nil {
		t.Fatal(err)
	}

	srv := &Server{}
	srv.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := &apiTrusted.Certificate
			if hello.ServerName == "api.quillrouter.com" {
				cert = &apiQuill.Certificate
			}
			if setter, ok := hello.Conn.(selectedLeafSetter); ok {
				setter.setSelectedLeafDER(cert.Certificate[0])
			}
			// Mirror the ACME production path: a later handshake for another
			// hostname updates the process-global leaf cache. The selected leaf
			// attached to the first connection must still remain stable.
			srv.setLeafDER(cert.Certificate[0])
			return cert, nil
		},
	}

	innerL := newPipeListener(t)
	defer innerL.Close()
	tlsL := srv.Wrap(innerL)
	pool := x509.NewCertPool()
	trustedLeaf, err := x509.ParseCertificate(apiTrusted.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse trustedrouter leaf: %v", err)
	}
	quillLeaf, err := x509.ParseCertificate(apiQuill.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse quillrouter leaf: %v", err)
	}
	pool.AddCert(trustedLeaf)
	pool.AddCert(quillLeaf)

	firstRelease := make(chan struct{})
	firstDone := make(chan []byte, 1)
	firstAccepted := make(chan struct{}, 1)
	go func() {
		conn, err := tlsL.Accept()
		if err != nil {
			firstDone <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := []byte{0}
		_, _ = conn.Read(buf)
		firstAccepted <- struct{}{}
		<-firstRelease
		firstDone <- SelectedLeafDER(conn)
	}()

	client1, err := innerL.dial()
	if err != nil {
		t.Fatalf("dial first: %v", err)
	}
	tc1 := tls.Client(client1, &tls.Config{
		RootCAs:    pool,
		ServerName: "api.trustedrouter.com",
		MinVersion: tls.VersionTLS12,
	})
	_ = tc1.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tc1.Handshake(); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if _, err := tc1.Write([]byte{1}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	<-firstAccepted

	secondDone := make(chan []byte, 1)
	go func() {
		conn, err := tlsL.Accept()
		if err != nil {
			secondDone <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := []byte{0}
		_, _ = conn.Read(buf)
		secondDone <- SelectedLeafDER(conn)
	}()

	client2, err := innerL.dial()
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	tc2 := tls.Client(client2, &tls.Config{
		RootCAs:    pool,
		ServerName: "api.quillrouter.com",
		MinVersion: tls.VersionTLS12,
	})
	_ = tc2.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tc2.Handshake(); err != nil {
		t.Fatalf("second handshake: %v", err)
	}
	if _, err := tc2.Write([]byte{1}); err != nil {
		t.Fatalf("second write: %v", err)
	}
	secondLeaf := <-secondDone

	close(firstRelease)
	firstLeaf := <-firstDone
	_ = tc1.Close()
	_ = tc2.Close()

	if !bytes.Equal(secondLeaf, apiQuill.Certificate.Certificate[0]) {
		t.Fatal("second connection did not record the quillrouter leaf")
	}
	if !bytes.Equal(srv.CurrentLeafDER(), apiQuill.Certificate.Certificate[0]) {
		t.Fatal("test setup failed: global leaf was not overwritten by second handshake")
	}
	if !bytes.Equal(firstLeaf, apiTrusted.Certificate.Certificate[0]) {
		t.Fatal("first connection leaf changed after another hostname handshake")
	}
}

func TestSelectedExporterTLS13(t *testing.T) {
	srv, err := NewSelfSigned("test.quill.local")
	if err != nil {
		t.Fatal(err)
	}
	innerL := newPipeListener(t)
	defer innerL.Close()
	tlsL := srv.Wrap(innerL)

	serverExporter := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := tlsL.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Read([]byte{0}); err != nil {
			serverErr <- err
			return
		}
		exporter, err := SelectedExporter(conn)
		if err != nil {
			serverErr <- err
			return
		}
		serverExporter <- exporter
	}()

	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(srv.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool.AddCert(leaf)
	client, err := innerL.dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	tc := tls.Client(client, &tls.Config{
		RootCAs:    pool,
		ServerName: "test.quill.local",
		MinVersion: tls.VersionTLS13,
	})
	_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	clientState := tc.ConnectionState()
	clientExporter, err := clientState.ExportKeyingMaterial(ExporterLabel, nil, ExporterLength)
	if err != nil {
		t.Fatalf("client exporter: %v", err)
	}
	if _, err := tc.Write([]byte{1}); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case err := <-serverErr:
		t.Fatalf("server: %v", err)
	case got := <-serverExporter:
		if len(got) != ExporterLength {
			t.Fatalf("exporter length = %d, want %d", len(got), ExporterLength)
		}
		if !bytes.Equal(got, clientExporter) {
			t.Fatal("server exporter did not match client exporter")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server exporter")
	}
}

func TestSelectedExporterDiffersAcrossIndependentTLS13Sessions(t *testing.T) {
	srv, err := NewSelfSigned("test.quill.local")
	if err != nil {
		t.Fatal(err)
	}
	innerL := newPipeListener(t)
	defer innerL.Close()
	tlsL := srv.Wrap(innerL)

	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(srv.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool.AddCert(leaf)

	// G6/RFC 9266 anti-relay closure rests on tls-exporter being derived from
	// the individual TLS session, not only from the enclave cert or process.
	sessionA := selectedExporterForLoopbackSession(t, tlsL, innerL, pool)
	sessionB := selectedExporterForLoopbackSession(t, tlsL, innerL, pool)
	if bytes.Equal(sessionA, sessionB) {
		t.Fatalf("independent TLS 1.3 sessions produced the same exporter: %x", sessionA)
	}
}

func selectedExporterForLoopbackSession(t *testing.T, tlsL net.Listener, innerL *pipeListener, pool *x509.CertPool) []byte {
	t.Helper()
	serverExporter := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := tlsL.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Read([]byte{0}); err != nil {
			serverErr <- err
			return
		}
		exporter, err := SelectedExporter(conn)
		if err != nil {
			serverErr <- err
			return
		}
		serverExporter <- exporter
	}()

	client, err := innerL.dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	tc := tls.Client(client, &tls.Config{
		RootCAs:    pool,
		ServerName: "test.quill.local",
		MinVersion: tls.VersionTLS13,
	})
	_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := tc.Write([]byte{1}); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = tc.Close()

	select {
	case err := <-serverErr:
		t.Fatalf("server: %v", err)
	case exporter := <-serverExporter:
		if len(exporter) != ExporterLength {
			t.Fatalf("exporter length = %d, want %d", len(exporter), ExporterLength)
		}
		return exporter
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server exporter")
	}
	return nil
}

func TestSelectedExporterErrors(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if _, err := SelectedExporter(server); err == nil || !strings.Contains(err.Error(), "not a TLS connection") {
		t.Fatalf("non-TLS error = %v, want not a TLS connection", err)
	}

	tls12 := fakeTLSStateConn{
		Conn: server,
		state: tls.ConnectionState{
			HandshakeComplete: true,
			Version:           tls.VersionTLS12,
		},
	}
	if _, err := SelectedExporter(tls12); err == nil || !strings.Contains(err.Error(), "requires TLS 1.3") {
		t.Fatalf("TLS 1.2 error = %v, want TLS 1.3 requirement", err)
	}

	incomplete := fakeTLSStateConn{
		Conn:  server,
		state: tls.ConnectionState{Version: tls.VersionTLS13},
	}
	if _, err := SelectedExporter(incomplete); err == nil || !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("incomplete handshake error = %v, want handshake error", err)
	}
}

// TestWrap_RejectsClientWithDifferentRoot ensures a client that doesn't
// trust the leaf gets rejected (basic confidence in the TLS config).
func TestWrap_RejectsClientWithDifferentRoot(t *testing.T) {
	srv, err := NewSelfSigned("test.quill.local")
	if err != nil {
		t.Fatal(err)
	}
	innerL := newPipeListener(t)
	defer innerL.Close()
	tlsL := srv.Wrap(innerL)

	go func() {
		conn, err := tlsL.Accept()
		if err != nil {
			return
		}
		// Drive the handshake by reading; the read will fail because the
		// client aborts, but we just need to consume the side from the server
		// goroutine so the test doesn't leak.
		_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
	}()

	client, err := innerL.dial()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	tc := tls.Client(client, &tls.Config{
		RootCAs:    x509.NewCertPool(), // empty pool: nothing trusted
		ServerName: "test.quill.local",
		MinVersion: tls.VersionTLS12,
	})
	_ = tc.SetDeadline(time.Now().Add(1 * time.Second))
	err = tc.Handshake()
	if err == nil {
		t.Fatal("handshake unexpectedly succeeded with empty trust pool")
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "trust") {
		t.Logf("note: handshake failed with non-cert message: %v (still rejected, OK)", err)
	}
}

// pipeListener is a net.Listener that uses net.Pipe so tests don't need
// actual sockets. dial() returns a client side; Accept() yields the server
// side of the same pipe.
type pipeListener struct {
	ch     chan net.Conn
	closed chan struct{}
}

func newPipeListener(t *testing.T) *pipeListener {
	t.Helper()
	return &pipeListener{
		ch:     make(chan net.Conn, 1),
		closed: make(chan struct{}),
	}
}

func (p *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-p.ch:
		return c, nil
	case <-p.closed:
		return nil, net.ErrClosed
	}
}

func (p *pipeListener) Close() error {
	select {
	case <-p.closed:
	default:
		close(p.closed)
	}
	return nil
}

func (p *pipeListener) Addr() net.Addr { return pipeAddr{} }

func (p *pipeListener) dial() (net.Conn, error) {
	c1, c2 := net.Pipe()
	return p.offer(c1, c2)
}

// dialBuffered uses a kernel-buffered local socket pair. TLS 1.3 writes its
// session ticket after the handshake, so the synchronous net.Pipe transport
// can otherwise deadlock until a deadline when the client has not begun its
// next read yet.
func (p *pipeListener) dialBuffered() (net.Conn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	files := []*os.File{
		os.NewFile(uintptr(fds[0]), "tls-client"),
		os.NewFile(uintptr(fds[1]), "tls-server"),
	}
	client, err := net.FileConn(files[0])
	if err != nil {
		_ = files[0].Close()
		_ = files[1].Close()
		return nil, err
	}
	server, err := net.FileConn(files[1])
	_ = files[0].Close()
	_ = files[1].Close()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return p.offer(client, server)
}

func (p *pipeListener) offer(client, server net.Conn) (net.Conn, error) {
	select {
	case p.ch <- server:
		return client, nil
	case <-p.closed:
		_ = client.Close()
		_ = server.Close()
		return nil, net.ErrClosed
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

type fakeTLSStateConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c fakeTLSStateConn) ConnectionState() tls.ConnectionState {
	return c.state
}

type resumptionHandshake struct {
	serverLeaf []byte
	clientLeaf []byte
	resumed    bool
}

type resumptionHarness struct {
	t      *testing.T
	server *Server
	inner  *pipeListener
	tls    net.Listener
	roots  *x509.CertPool
}

func newResumptionHarness(
	t *testing.T,
	certificates []*tls.Certificate,
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
) *resumptionHarness {
	t.Helper()
	srv := &Server{singleCert: true} // recreate the pre-c54e90d6 global pre-seed
	base := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	base.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := getCertificate(hello)
		if err == nil && cert != nil && len(cert.Certificate) > 0 {
			if setter, ok := hello.Conn.(selectedLeafSetter); ok {
				setter.setSelectedLeafDER(cert.Certificate[0])
			}
			srv.setLeafDER(cert.Certificate[0])
		}
		return cert, err
	}
	enablePerSNIResumption(base)
	srv.tlsConfig = base

	inner := newPipeListener(t)
	t.Cleanup(func() { _ = inner.Close() })

	roots := x509.NewCertPool()
	for _, cert := range certificates {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		roots.AddCert(leaf)
	}
	return &resumptionHarness{t: t, server: srv, inner: inner, tls: srv.Wrap(inner), roots: roots}
}

func (h *resumptionHarness) dial(sni string, cache tls.ClientSessionCache) resumptionHandshake {
	return h.dialWithConfig(sni, cache, false)
}

func (h *resumptionHarness) dialWithoutHostnameValidation(sni string, cache tls.ClientSessionCache) resumptionHandshake {
	return h.dialWithConfig(sni, cache, true)
}

func (h *resumptionHarness) dialWithConfig(
	sni string,
	cache tls.ClientSessionCache,
	insecureSkipVerify bool,
) resumptionHandshake {
	h.t.Helper()
	serverLeaf := make(chan []byte, 1)
	go func() {
		conn, err := h.tls.Accept()
		if err != nil {
			serverLeaf <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, []byte{0}); err != nil {
			serverLeaf <- nil
			return
		}
		if _, err := conn.Write([]byte{1}); err != nil {
			serverLeaf <- nil
			return
		}
		serverLeaf <- SelectedLeafDER(conn)
	}()

	raw, err := h.inner.dialBuffered()
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	client := tls.Client(raw, &tls.Config{
		RootCAs:            h.roots,
		ServerName:         sni,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
		ClientSessionCache: cache,
		InsecureSkipVerify: insecureSkipVerify, // test-only: see cross-SNI case
	})
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := client.Handshake(); err != nil {
		h.t.Fatalf("handshake %s: %v", sni, err)
	}
	if _, err := client.Write([]byte{1}); err != nil {
		h.t.Fatalf("write %s: %v", sni, err)
	}
	if _, err := io.ReadFull(client, []byte{0}); err != nil {
		h.t.Fatalf("read %s: %v", sni, err)
	}
	state := client.ConnectionState()
	_ = client.Close()
	return resumptionHandshake{
		serverLeaf: <-serverLeaf,
		clientLeaf: state.PeerCertificates[0].Raw,
		resumed:    state.DidResume,
	}
}

// TestResumedSessionNeverAttestsAnotherHostnamesLeaf is the exact live
// c54e90d6 sequence: full A, full B (overwriting the process-global leaf), then
// resume A. The harness deliberately restores the old global pre-seed so this
// turns red with B's leaf if the GetConfigForClient isolation is removed.
func TestResumedSessionNeverAttestsAnotherHostnamesLeaf(t *testing.T) {
	hostA, hostB := "api.trustedrouter.com", "api.uptimerouter.com"
	serverA, err := NewSelfSigned(hostA)
	if err != nil {
		t.Fatal(err)
	}
	serverB, err := NewSelfSigned(hostB)
	if err != nil {
		t.Fatal(err)
	}
	certA, certB := &serverA.Certificate, &serverB.Certificate
	h := newResumptionHarness(t, []*tls.Certificate{certA, certB}, func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == hostB {
			return certB, nil
		}
		return certA, nil
	})
	cache := tls.NewLRUClientSessionCache(8)

	if got := h.dial(hostA, cache); got.resumed || !bytes.Equal(got.serverLeaf, certA.Certificate[0]) {
		t.Fatalf("full A = resumed %v, leaf %x", got.resumed, sha256.Sum256(got.serverLeaf))
	}
	if got := h.dial(hostB, cache); got.resumed || !bytes.Equal(got.serverLeaf, certB.Certificate[0]) {
		t.Fatalf("full B = resumed %v, leaf %x", got.resumed, sha256.Sum256(got.serverLeaf))
	}
	if !bytes.Equal(h.server.CurrentLeafDER(), certB.Certificate[0]) {
		t.Fatal("precondition failed: B did not overwrite the process-global leaf")
	}

	got := h.dial(hostA, cache)
	if !got.resumed {
		t.Fatal("same-hostname TLS 1.3 session did not resume")
	}
	if !bytes.Equal(got.clientLeaf, certA.Certificate[0]) || !bytes.Equal(got.serverLeaf, certA.Certificate[0]) {
		t.Fatalf("resumed A leaf mismatch: client_is_A=%v server_is_A=%v server_is_B=%v",
			bytes.Equal(got.clientLeaf, certA.Certificate[0]),
			bytes.Equal(got.serverLeaf, certA.Certificate[0]),
			bytes.Equal(got.serverLeaf, certB.Certificate[0]))
	}
}

// oneSessionCache deliberately ignores crypto/tls's per-host cache key. The
// cross-SNI test also disables the test client's hostname check, which would
// otherwise decline to offer A's ticket for B before the server sees it. The
// server must reject the adversarially offered ticket and handshake B in full.
type oneSessionCache struct {
	state *tls.ClientSessionState
}

func (c *oneSessionCache) Get(string) (*tls.ClientSessionState, bool) {
	return c.state, c.state != nil
}

func (c *oneSessionCache) Put(_ string, state *tls.ClientSessionState) {
	c.state = state
}

func TestSessionTicketCannotResumeAcrossSNI(t *testing.T) {
	hostA, hostB := "api.trustedrouter.com", "api.uptimerouter.com"
	serverA, err := NewSelfSigned(hostA)
	if err != nil {
		t.Fatal(err)
	}
	serverB, err := NewSelfSigned(hostB)
	if err != nil {
		t.Fatal(err)
	}
	certA, certB := &serverA.Certificate, &serverB.Certificate
	h := newResumptionHarness(t, []*tls.Certificate{certA, certB}, func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == hostB {
			return certB, nil
		}
		return certA, nil
	})
	cache := new(oneSessionCache)
	_ = h.dialWithoutHostnameValidation(hostA, cache)

	got := h.dialWithoutHostnameValidation(hostB, cache)
	if got.resumed {
		t.Fatal("B resumed a TLS session ticket minted for A")
	}
	if !bytes.Equal(got.clientLeaf, certB.Certificate[0]) || !bytes.Equal(got.serverLeaf, certB.Certificate[0]) {
		t.Fatal("cross-SNI ticket rejection did not fall back to B's exact leaf")
	}
}

func TestLeafRotationInvalidatesOldSessionTickets(t *testing.T) {
	host := "api.trustedrouter.com"
	serverV1, err := NewSelfSigned(host)
	if err != nil {
		t.Fatal(err)
	}
	serverV2, err := NewSelfSigned(host)
	if err != nil {
		t.Fatal(err)
	}
	certV1, certV2 := &serverV1.Certificate, &serverV2.Certificate
	active := certV1
	h := newResumptionHarness(t, []*tls.Certificate{certV1, certV2}, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return active, nil
	})
	cache := tls.NewLRUClientSessionCache(8)
	_ = h.dial(host, cache)

	active = certV2
	rotated := h.dial(host, cache)
	if rotated.resumed {
		t.Fatal("pre-rotation ticket resumed after the hostname's leaf changed")
	}
	if !bytes.Equal(rotated.serverLeaf, certV2.Certificate[0]) {
		t.Fatal("post-rotation handshake did not bind the new leaf")
	}
	if got := h.dial(host, cache); !got.resumed || !bytes.Equal(got.serverLeaf, certV2.Certificate[0]) {
		t.Fatal("a ticket minted after rotation did not resume against the new leaf")
	}
}

func TestACMEResumptionKillSwitch(t *testing.T) {
	t.Run("default is per-SNI resumption", func(t *testing.T) {
		t.Setenv("QUILL_TLS_RESUMPTION", "")
		server, err := NewACME("api.trustedrouter.com,api.uptimerouter.com", "", "memory", "", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if server.tlsConfig.SessionTicketsDisabled || server.tlsConfig.GetConfigForClient == nil {
			t.Fatal("ACME per-SNI resumption is not enabled by default")
		}
	})

	t.Run("off restores disabled tickets", func(t *testing.T) {
		t.Setenv("QUILL_TLS_RESUMPTION", "off")
		server, err := NewACME("api.trustedrouter.com,api.uptimerouter.com", "", "memory", "", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if !server.tlsConfig.SessionTicketsDisabled || server.tlsConfig.GetConfigForClient != nil {
			t.Fatal("QUILL_TLS_RESUMPTION=off did not restore disabled tickets")
		}
	})
}
