package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestServeOnePublicModelsIsAnonymousOnAttestedOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Fatalf("control-plane path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-TrustedRouter-Internal-Token") != "" {
			t.Fatalf("public catalog received credentials: %#v", r.Header)
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"trustedrouter/auto"}]}`)
	}))
	defer server.Close()

	conn := newScriptedConn("GET /v1/models HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n", nil)
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)

	out := conn.writes.String()
	if !strings.Contains(out, "HTTP/1.1 200 OK") {
		t.Fatalf("response = %s", out)
	}
	if !strings.Contains(out, "Access-Control-Allow-Origin: *") {
		t.Fatalf("missing public CORS header: %s", out)
	}
	if got := httpBody(t, out); !strings.Contains(got, "trustedrouter/auto") {
		t.Fatalf("body = %s", got)
	}
}

func TestServeOneModelsOnlyAllowsAnonymousGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"trustedrouter/auto"}]}`)
	}))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())

	request := "POST /v1/models HTTP/1.1\r\nHost: api.trustedrouter.com\r\nContent-Length: 2\r\n\r\n{}"
	conn := newScriptedConn(request, nil)
	serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)
	if !strings.Contains(conn.writes.String(), "HTTP/1.1 401 Unauthorized") {
		t.Fatalf("response = %s", conn.writes.String())
	}
}

func TestServeOnePublicModelsHidesControlPlaneFailureBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "private upstream detail", http.StatusInternalServerError)
	}))
	defer server.Close()

	conn := newScriptedConn("GET /v1/models HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n", nil)
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)

	out := conn.writes.String()
	if !strings.Contains(out, fmt.Sprintf("HTTP/1.1 %d", http.StatusServiceUnavailable)) {
		t.Fatalf("response = %s", out)
	}
	if strings.Contains(out, "private upstream detail") {
		t.Fatalf("control-plane response leaked: %s", out)
	}
}
