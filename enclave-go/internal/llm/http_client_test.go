package llm

import (
	"net/http"
	"testing"
	"time"
)

func TestPooledHTTPClientUsesTunedTransport(t *testing.T) {
	client := pooledHTTPClient(30 * time.Second)
	if client.Timeout != 30*time.Second {
		t.Fatalf("timeout = %s, want 30s", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = false, want true")
	}
	if transport.MaxIdleConns < 1024 {
		t.Fatalf("MaxIdleConns = %d, want at least 1024", transport.MaxIdleConns)
	}
	if transport.MaxIdleConnsPerHost < 128 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want at least 128", transport.MaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout <= 0 {
		t.Fatal("IdleConnTimeout must be positive")
	}
}
