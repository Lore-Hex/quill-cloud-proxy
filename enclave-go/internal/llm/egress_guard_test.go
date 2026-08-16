package llm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixedIPResolver []netip.Addr

func (r fixedIPResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r...), nil
}

type blockingIPResolver struct{}

func (blockingIPResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestAllowedPublicIPRefusesUnsafeClasses(t *testing.T) {
	for _, value := range []string{
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
		"224.0.0.1",
		"0.0.0.0",
		"192.0.2.1",
		"::1",
		"fe80::1",
		"ff02::1",
		"::ffff:10.0.0.1",
		"64:ff9b:1::1",
		"2002::1",
		"3fff::1",
		"5f00::1",
	} {
		t.Run(value, func(t *testing.T) {
			if allowedPublicIP(netip.MustParseAddr(value)) {
				t.Fatalf("unsafe address %s was allowed", value)
			}
		})
	}
	if !allowedPublicIP(netip.MustParseAddr("8.8.8.8")) || !allowedPublicIP(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("known public addresses were refused")
	}
	for _, value := range []string{"192.0.0.9", "192.0.0.10", "192.88.99.1", "2001:3::1"} {
		if !allowedPublicIP(netip.MustParseAddr(value)) {
			t.Fatalf("safe_egress.py public exception %s was refused", value)
		}
	}
}

func TestGuardRefusesMixedDNSAnswersBeforeDial(t *testing.T) {
	dialed := false
	client, err := NewGuardedHTTPClient("https://owner.example/v1", EgressGuardOptions{
		ConnectTimeout: time.Second,
		Resolver: fixedIPResolver{
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("127.0.0.1"),
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unexpected dial")
		},
	})
	if err != nil {
		t.Fatalf("NewGuardedHTTPClient: %v", err)
	}
	_, err = client.Get("https://owner.example/v1/chat/completions")
	var guardErr *EgressGuardError
	if !errors.As(err, &guardErr) || dialed {
		t.Fatalf("request error = %v, dialed=%v", err, dialed)
	}
}

func TestGuardRefusesRedirect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.example/secret", http.StatusFound)
	}))
	defer server.Close()
	client := guardedTestClient(t, server, "example.com")

	response, err := client.Get("https://example.com/chat/completions")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestGuardTLSUsesRegisteredHostAsServerName(t *testing.T) {
	var mu sync.Mutex
	seenServerName := ""
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.StartTLS()
	server.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		seenServerName = hello.ServerName
		mu.Unlock()
		return nil, nil
	}
	defer server.Close()

	client := guardedTestClient(t, server, "example.com")
	response, err := client.Get("https://example.com/chat/completions")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	response.Body.Close()
	mu.Lock()
	got := seenServerName
	mu.Unlock()
	if got != "example.com" {
		t.Fatalf("TLS ServerName = %q", got)
	}
}

func TestGuardBoundsConnect(t *testing.T) {
	client, err := NewGuardedHTTPClient("https://timeout.example", EgressGuardOptions{
		ConnectTimeout: 25 * time.Millisecond,
		TotalTimeout:   time.Second,
		Resolver:       fixedIPResolver{netip.MustParseAddr("8.8.8.8")},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatalf("NewGuardedHTTPClient: %v", err)
	}
	started := time.Now()
	_, err = client.Get("https://timeout.example/chat/completions")
	if err == nil || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("connect error = %v after %s", err, time.Since(started))
	}
}

func TestGuardBoundsDNSWithConnectBudget(t *testing.T) {
	client, err := NewGuardedHTTPClient("https://timeout.example", EgressGuardOptions{
		ConnectTimeout: 25 * time.Millisecond,
		TotalTimeout:   time.Second,
		Resolver:       blockingIPResolver{},
	})
	if err != nil {
		t.Fatalf("NewGuardedHTTPClient: %v", err)
	}
	started := time.Now()
	_, err = client.Get("https://timeout.example/chat/completions")
	var guardErr *EgressGuardError
	if !errors.As(err, &guardErr) || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("DNS error = %v after %s", err, time.Since(started))
	}
}

func TestGuardStartsIdleBudgetAfterFirstBodyByte(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		time.Sleep(75 * time.Millisecond)
		_, _ = io.WriteString(w, "a")
		flusher.Flush()
		time.Sleep(75 * time.Millisecond)
		_, _ = io.WriteString(w, "b")
	}))
	server.StartTLS()
	defer server.Close()

	client := guardedTestClientWithIdle(t, server, "example.com", 30*time.Millisecond)
	response, err := client.Get("https://example.com/chat/completions")
	if err != nil {
		t.Fatalf("Get before first body byte: %v", err)
	}
	defer response.Body.Close()
	buffer := make([]byte, 1)
	if _, err := io.ReadFull(response.Body, buffer); err != nil || string(buffer) != "a" {
		t.Fatalf("first body byte = %q, err=%v", buffer, err)
	}
	_, err = io.ReadFull(response.Body, buffer)
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("second read error = %v, want idle timeout", err)
	}
}

func guardedTestClient(t *testing.T, server *httptest.Server, registeredHost string) *http.Client {
	return guardedTestClientWithIdle(t, server, registeredHost, time.Second)
}

func guardedTestClientWithIdle(t *testing.T, server *httptest.Server, registeredHost string, idle time.Duration) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	address := server.Listener.Addr().String()
	client, err := NewGuardedHTTPClient("https://"+registeredHost, EgressGuardOptions{
		ConnectTimeout:        time.Second,
		ResponseHeaderTimeout: time.Second,
		IdleTimeout:           idle,
		TotalTimeout:          time.Second,
		RootCAs:               pool,
		Resolver:              fixedIPResolver{netip.MustParseAddr("8.8.8.8")},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	})
	if err != nil {
		t.Fatalf("NewGuardedHTTPClient: %v", err)
	}
	return client
}

func TestGuardRejectsNonHTTPS(t *testing.T) {
	_, err := NewGuardedHTTPClient("http://owner.example", EgressGuardOptions{})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("error = %v", err)
	}
}
