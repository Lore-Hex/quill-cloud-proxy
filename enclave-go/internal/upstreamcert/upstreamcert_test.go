package upstreamcert

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type fakeConn struct{ id string }

func (*fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*fakeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*fakeConn) Close() error                     { return nil }
func (*fakeConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (c *fakeConn) RemoteAddr() net.Addr           { return fakeAddr(c.id) }
func (*fakeConn) SetDeadline(time.Time) error      { return nil }
func (*fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (*fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }

func TestDialTLSContextRecordsAndRemovesPeerLeaf(t *testing.T) {
	certificate, leaf := newTestCertificate(t, 1)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	config := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}
	dialContext := func(context.Context, string, string) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			tlsServer := tls.Server(serverConn, serverConfig)
			if handshakeErr := tlsServer.Handshake(); handshakeErr == nil {
				_, _ = io.Copy(io.Discard, tlsServer)
			}
			_ = tlsServer.Close()
		}()
		return clientConn, nil
	}
	registry := &Registry{}
	dial := registry.DialTLSContext(dialContext, config, time.Second)
	conn, err := dial(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialTLSContext: %v", err)
	}
	state := conn.(*tls.Conn).ConnectionState()
	digest := sha256.Sum256(state.PeerCertificates[0].Raw)
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	if got, ok := registry.Lookup(conn); !ok || got != want {
		t.Fatalf("Lookup = %q, %v, want %q, true", got, ok, want)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got, ok := registry.Lookup(conn); ok {
		t.Fatalf("closed connection remained registered as %q", got)
	}
}

func newTestCertificate(t *testing.T, serial int64) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: privateKey}, leaf
}

func serveTestResponse(conn *tls.Conn, reader *bufio.Reader, closeConnection bool) error {
	request, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, request.Body)
	_ = request.Body.Close()
	connectionHeader := ""
	if closeConnection {
		connectionHeader = "Connection: close\r\n"
	}
	_, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n%s\r\nok", connectionHeader)
	return err
}

func TestHTTPTransportAttributesReusedAndRetriedTLSConnections(t *testing.T) {
	certA, leafA := newTestCertificate(t, 1)
	certB, leafB := newTestCertificate(t, 2)
	roots := x509.NewCertPool()
	roots.AddCert(leafA)
	roots.AddCert(leafB)
	clientTLSConfig := &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	var dials atomic.Int32
	dialContext := func(context.Context, string, string) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		dialNumber := dials.Add(1)
		certificate := certA
		if dialNumber > 1 {
			certificate = certB
		}
		go func() {
			tlsServer := tls.Server(serverConn, &tls.Config{
				Certificates: []tls.Certificate{certificate},
				MinVersion:   tls.VersionTLS12,
			})
			defer tlsServer.Close()
			if err := tlsServer.Handshake(); err != nil {
				return
			}
			reader := bufio.NewReader(tlsServer)
			if dialNumber == 1 {
				if err := serveTestResponse(tlsServer, reader, false); err != nil {
					return
				}
				// A second successful response proves keep-alive reuse.
				if err := serveTestResponse(tlsServer, reader, false); err != nil {
					return
				}
				// Dropping the third request without a response makes net/http retry
				// that idempotent request on dial 2.
				request, err := http.ReadRequest(reader)
				if err == nil {
					_, _ = io.Copy(io.Discard, request.Body)
					_ = request.Body.Close()
				}
				return
			}
			_ = serveTestResponse(tlsServer, reader, true)
		}()
		return clientConn, nil
	}
	registry := &Registry{}
	base := &http.Transport{
		DialTLSContext:  registry.DialTLSContext(dialContext, clientTLSConfig, time.Second),
		TLSClientConfig: clientTLSConfig,
	}
	client := &http.Client{Transport: &Transport{Base: base, Registry: registry}}
	defer client.CloseIdleConnections()
	ctx := WithCarrier(context.Background())

	request := func() string {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/test", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		fingerprint, _ := FromContext(ctx)
		return fingerprint
	}

	digestA := sha256.Sum256(leafA.Raw)
	digestB := sha256.Sum256(leafB.Raw)
	if got, want := request(), base64.RawURLEncoding.EncodeToString(digestA[:]); got != want {
		t.Fatalf("first request fingerprint = %q, want %q", got, want)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("first request dials = %d, want 1", got)
	}
	if got, want := request(), base64.RawURLEncoding.EncodeToString(digestA[:]); got != want {
		t.Fatalf("reused request fingerprint = %q, want %q", got, want)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("reused request dials = %d, want 1", got)
	}
	if got, want := request(), base64.RawURLEncoding.EncodeToString(digestB[:]); got != want {
		t.Fatalf("retried request fingerprint = %q, want serving connection %q", got, want)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("retried request dials = %d, want 2", got)
	}
}

func TestTransportAttributesReuseDifferentConnectionsRetryAndAmbiguity(t *testing.T) {
	connA := &fakeConn{id: "a"}
	connB := &fakeConn{id: "b"}
	unknown := &fakeConn{id: "unknown"}
	registry := &Registry{}
	registry.Record(connA, []byte("leaf-a"))
	registry.Record(connB, []byte("leaf-b"))
	fingerprintA, _ := registry.Lookup(connA)
	fingerprintB, _ := registry.Lookup(connB)

	tests := []struct {
		name string
		uses [][]net.Conn
		want []string
	}{
		{
			name: "two sequential requests reuse one connection",
			uses: [][]net.Conn{{connA}, {connA}},
			want: []string{fingerprintA, fingerprintA},
		},
		{
			name: "two requests use different connections",
			uses: [][]net.Conn{{connA}, {connB}},
			want: []string{fingerprintA, fingerprintB},
		},
		{
			name: "transport retry switches to serving connection",
			uses: [][]net.Conn{{connA, connB}},
			want: []string{fingerprintB},
		},
		{
			name: "unregistered serving connection is ambiguous",
			uses: [][]net.Conn{{unknown}},
			want: []string{""},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requestNumber := 0
			base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				trace := httptrace.ContextClientTrace(req.Context())
				for _, conn := range tc.uses[requestNumber] {
					trace.GotConn(httptrace.GotConnInfo{Conn: conn})
				}
				requestNumber++
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(http.NoBody),
					Request:    req,
				}, nil
			})
			transport := &Transport{Base: base, Registry: registry}
			ctx := WithCarrier(context.Background())
			for i, want := range tc.want {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := transport.RoundTrip(req)
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				_ = response.Body.Close()
				got, _ := FromContext(ctx)
				if got != want {
					t.Fatalf("request %d fingerprint = %q, want %q", i, got, want)
				}
			}
		})
	}
}

func TestConcurrentAttributionsOnOneRequestContextNeverYieldACert(t *testing.T) {
	// Two attributions in flight on one carrier mean the serving connection
	// cannot be known — even when both finish certain with the SAME
	// fingerprint, the carrier must omit rather than guess. This is the
	// concurrency half of the never-guess rule.
	ctx := WithCarrier(context.Background())
	first, ok := begin(ctx)
	if !ok {
		t.Fatal("begin first")
	}
	second, ok := begin(ctx)
	if !ok {
		t.Fatal("begin second")
	}
	first.finish("sha-one", true)
	second.finish("sha-one", true)
	if cert, ok := FromContext(ctx); ok {
		t.Fatalf("concurrent attributions yielded cert %q; must omit", cert)
	}
	// After a Reset, a single clean attribution works again — ambiguity is
	// per-attempt state, not a permanent poisoning.
	Reset(ctx)
	third, ok := begin(ctx)
	if !ok {
		t.Fatal("begin third")
	}
	third.finish("sha-two", true)
	if cert, ok := FromContext(ctx); !ok || cert != "sha-two" {
		t.Fatalf("clean post-reset attribution = %q, %v", cert, ok)
	}
}
