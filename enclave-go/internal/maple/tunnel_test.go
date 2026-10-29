package maple

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTunnelRejectsEveryOtherDestination(t *testing.T) {
	for _, target := range []string{"evil.example:443", "enclave.trymaple.ai:80", "enclave.trymaple.ai.evil:443", "https://enclave.trymaple.ai:443/", "enclave.trymaple.ai:443?x=1"} {
		r := httptest.NewRequest(http.MethodConnect, target, nil)
		w := httptest.NewRecorder()
		tunnelHandler(t.Context(), func() (net.Conn, error) { t.Fatal("forbidden dial"); return nil, nil }).ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("target=%s status=%d", target, w.Code)
		}
	}
	w := httptest.NewRecorder()
	tunnelHandler(t.Context(), func() (net.Conn, error) { t.Fatal("plain HTTP dial"); return nil, nil }).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://enclave.trymaple.ai:443/", nil))
	if w.Code != http.StatusForbidden {
		t.Fatal(w.Code)
	}
}

func TestTunnelRelaysOpaqueBytesAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	upstream, peer := net.Pipe()
	defer peer.Close()
	server := httptest.NewServer(tunnelHandler(ctx, func() (net.Conn, error) { return upstream, nil }))
	defer server.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT enclave.trymaple.ai:443 HTTP/1.1\r\nHost: enclave.trymaple.ai:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("response=%v err=%v", response, err)
	}
	done := make(chan error, 1)
	go func() { _, err := io.WriteString(conn, "opaque-tls"); done <- err }()
	buf := make([]byte, len("opaque-tls"))
	if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "opaque-tls" {
		t.Fatalf("got=%q err=%v", buf, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("cancelled tunnel remained open")
	}
}
