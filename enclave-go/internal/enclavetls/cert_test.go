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
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
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

func TestNewACME_ConfiguresTLSALPNInMemory(t *testing.T) {
	srv, err := NewACME("api.quillrouter.com", "", "", "", "")
	if err != nil {
		t.Fatalf("NewACME: %v", err)
	}
	if srv.tlsConfig == nil {
		t.Fatal("tlsConfig is nil")
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
	select {
	case p.ch <- c2:
		return c1, nil
	case <-p.closed:
		_ = c1.Close()
		_ = c2.Close()
		return nil, net.ErrClosed
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }
