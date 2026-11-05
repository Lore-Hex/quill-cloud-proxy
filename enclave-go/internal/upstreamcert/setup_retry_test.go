package upstreamcert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type timeoutConn struct {
	fakeConn
	closed bool
}

func (*timeoutConn) Read([]byte) (int, error) { return 0, context.DeadlineExceeded }
func (c *timeoutConn) Close() error           { c.closed = true; return nil }

func TestTLSSetupTimeoutRetriesBeforeAnyHTTPRequest(t *testing.T) {
	certificate, leaf := newTestCertificate(t, 50)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	failed := &timeoutConn{}
	calls := 0
	serverDone := make(chan struct{})
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return failed, nil
		}
		client, server := net.Pipe()
		go func() {
			defer close(serverDone)
			peer := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate}})
			defer peer.Close()
			if err := peer.Handshake(); err == nil {
				_, _ = io.Copy(io.Discard, peer)
			}
		}()
		return client, nil
	}
	registry := &Registry{}
	conn, err := registry.DialTLSContext(dial, &tls.Config{RootCAs: roots}, time.Second)(t.Context(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !failed.closed {
		t.Fatalf("calls=%d failed-connection-closed=%t", calls, failed.closed)
	}
	if _, found := registry.Lookup(conn); !found {
		t.Fatal("verified connection missing its certificate attribution")
	}
	_ = conn.Close()
	<-serverDone
}

func TestTLSSetupRetryIsBoundedAndHonorsCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		calls := 0
		dial := func(context.Context, string, string) (net.Conn, error) {
			calls++
			if canceled {
				cancel()
			}
			return nil, context.DeadlineExceeded
		}
		_, err := (&Registry{}).DialTLSContext(dial, nil, time.Second)(ctx, "tcp", "example.com:443")
		cancel()
		want := 2
		if canceled {
			want = 1
		}
		if calls != want || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("canceled=%t calls=%d err=%v", canceled, calls, err)
		}
	}
}

func TestTLSSetupDoesNotRetryCertificateFailure(t *testing.T) {
	certificate, _ := newTestCertificate(t, 51)
	calls := 0
	serverDone := make(chan struct{})
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls++
		client, server := net.Pipe()
		go func() {
			defer close(serverDone)
			peer := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate}})
			defer peer.Close()
			_ = peer.Handshake()
		}()
		return client, nil
	}
	_, err := (&Registry{}).DialTLSContext(dial, &tls.Config{RootCAs: x509.NewCertPool()}, time.Second)(t.Context(), "tcp", "example.com:443")
	var certificateError x509.UnknownAuthorityError
	if calls != 1 || !errors.As(err, &certificateError) {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
	<-serverDone
}
