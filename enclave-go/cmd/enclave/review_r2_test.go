package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowcoord"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speculation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestReviewR2InvalidCredentialClosesWarmCoverageThroughHandler(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/gateway/authorize" {
			io.WriteString(w, `{"data":{}}`)
			return
		}
		calls++
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"type":"invalid_api_key","message":"Invalid API key"}}`)
	}))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	c := literalShadowCoordinator(t)
	gateway.ConfigureSpeculation(t.Context(), c)
	ctx, _ := trustedrouter.WithAPIKeyLookupHash(t.Context(), strings.Repeat("b", 64))
	body := `{"model":"fixture-text","messages":[{"role":"user","content":"hello"}],"stream":true,"max_tokens":128,"provider":{"usage":"Credits"}}`
	conn := newScriptedConn(fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer invalid-key\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body), nil)
	serveOne(ctx, conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
	if calls != 1 || !strings.Contains(conn.writes.String(), "401") {
		t.Fatal(calls, conn.writes.String())
	}
	parsed := shadowcoord.ParseRequest([]byte(body))
	d := c.Predecision(strings.Repeat("a", 64), speculation.ParsedRequest{Body: parsed, RouteType: "chat.completions", CallerIdempotency: speculation.CaptureCallerIdempotency(false, parsed)}).Decision()
	if !d.Eligible {
		t.Fatalf("one ordinary invalid-key 401 closed unrelated cached rights: %+v", d)
	}
}

func TestReviewR2PartialKeyScopeThroughHandler(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/gateway/authorize" {
			io.WriteString(w, `{"data":{}}`)
			return
		}
		calls++
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"type":"invalid_api_key","message":"Invalid API key"},"data":{"workspace_id":"w"}}`)
	}))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	c := literalShadowCoordinator(t)
	gateway.ConfigureSpeculation(t.Context(), c)
	ctx, _ := trustedrouter.WithAPIKeyLookupHash(t.Context(), strings.Repeat("a", 64))
	body := `{"model":"fixture-text","messages":[{"role":"user","content":"hello"}],"stream":true,"max_tokens":128,"provider":{"usage":"Credits"}}`
	conn := newScriptedConn(fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer known-key\r\nIdempotency-Key: caller-supplied\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body), nil)
	serveOne(ctx, conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
	if calls != 1 || !strings.Contains(conn.writes.String(), "401") {
		t.Fatal(calls, conn.writes.String())
	}
	parsed := shadowcoord.ParseRequest([]byte(body))
	d := c.Predecision(strings.Repeat("a", 64), speculation.ParsedRequest{Body: parsed, RouteType: "chat.completions", CallerIdempotency: speculation.CaptureCallerIdempotency(false, parsed)}).Decision()
	if d.Eligible {
		t.Fatalf("ordinary key-invalid 401 with workspace-only metadata left revoked key eligible: %+v", d)
	}
}
