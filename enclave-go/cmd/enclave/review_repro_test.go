package main

import (
	"context"
	"fmt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowcoord"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speculation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type reviewSecondGuard struct{ calls int }

func (g *reviewSecondGuard) BeforeCredentialCheck(context.Context, string) error {
	g.calls++
	if g.calls >= 2 {
		return &trustedrouter.ControlPlaneError{StatusCode: 401, Type: "auth_cached_reject", Message: "concurrent revoke"}
	}
	return nil
}
func (g *reviewSecondGuard) AfterCredentialCheck(context.Context, string, error) {}
func TestReviewHandlerEarlyCredentialReturnLeaksSlot(t *testing.T) {
	netCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { netCalls++; io.WriteString(w, `{"data":{}}`) }))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	guard := &reviewSecondGuard{}
	gateway.SetCredentialGuard(guard)
	c := literalShadowCoordinator(t)
	gateway.ConfigureSpeculation(t.Context(), c)
	ctx, _ := trustedrouter.WithAPIKeyLookupHash(t.Context(), strings.Repeat("a", 64))
	body := `{"model":"fixture-text","messages":[{"role":"user","content":"hello"}],"stream":true,"max_tokens":128,"provider":{"usage":"Credits"}}`
	conn := newScriptedConn(fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer key\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body), nil)
	serveOne(ctx, conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
	if guard.calls < 2 || netCalls != 0 || !strings.Contains(conn.writes.String(), "401") {
		t.Fatal(guard.calls, netCalls, conn.writes.String())
	}
	eligible := false
	for len(c.Records()) > 0 {
		r := <-c.Records()
		if r.Kind == "predecision" && r.Decision.Eligible {
			eligible = true
		}
	}
	if !eligible {
		t.Fatal("test did not reach eligible predecision")
	}
	parsed := shadowcoord.ParseRequest([]byte(body))
	d := c.Predecision(strings.Repeat("a", 64), speculation.ParsedRequest{Body: parsed, RouteType: "chat.completions", CallerIdempotency: speculation.CaptureCallerIdempotency(false, parsed)}).Decision()
	if d.Reason == "simulated-concurrency" {
		t.Fatalf("401 completed with no authorize call but workspace remains busy: %+v", d)
	}
}
