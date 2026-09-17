package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type confidentialSNIConn struct {
	*scriptedConn
	sni string
}

func (c *confidentialSNIConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{ServerName: c.sni}
}

func TestConfidentialHostRejectsBeforeAuthorization(t *testing.T) {
	for _, tc := range []struct{ name, host, sni string }{
		{"host", "api.confidential.trustedrouter.com", "api.trustedrouter.com"},
		{"sni cannot be bypassed", "api.trustedrouter.com", "api.confidential.trustedrouter.com"},
		{"sni without host", "", "api.confidential.trustedrouter.com"},
		{"quill", "api.confidential.quillrouter.com", ""},
		{"ally", "api.confidential.allyrouter.com", ""},
		{"uptime case and port", "API.CONFIDENTIAL.UPTIMEROUTER.COM.:443", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, body := range []string{`{}`, `{"provider":null}`, `{"provider":{}}`, `{"provider":{"min_privacy":"zdr"}}`, `{"provider":{"min_privacy":"any"}}`, `{"provider":{"min_privacy":"e2e"}}`, `{"provider":{"min_privacy":"confidential"},"Provider":null}`} {
				header := ""
				if tc.host != "" {
					header = "Host: " + tc.host + "\r\n"
				}
				raw := fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\n%sContent-Length: %d\r\n\r\n%s", header, len(body), body)
				conn := &confidentialSNIConn{newScriptedConn(raw, nil), tc.sni}
				serveOne(context.Background(), conn, auth.New(nil), nil, nil, nil, nil, nil)
				if got := conn.writes.String(); !strings.Contains(got, `"code":"confidential_privacy_required"`) || !strings.Contains(got, "400 Bad Request") {
					t.Fatalf("body=%s: %s", body, got)
				}
			}
		})
	}
}

func TestConfidentialHostRequestValidation(t *testing.T) {
	gateway := trustedrouter.New("https://control.invalid", "internal", nil)
	valid := []byte(`{"provider":{"min_privacy":"confidential","only":["tinfoil"],"zdr":true}}`)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses", "/v1/messages", "/v1/responses/input_tokens"} {
		if err := validateConfidentialHostRequest("POST", path, valid, gateway); err != nil {
			t.Fatal(err)
		}
		if err := validateConfidentialHostRequest("POST", path, valid, nil); err == nil || err.StatusCode != 503 {
			t.Fatalf("unguarded local gateway: %v", err)
		}
	}
	for _, path := range []string{"/v1/embeddings", "/v1/images/generations", "/v1/videos", "/v1/files", "/v1/batches", "/new-api"} {
		if err := validateConfidentialHostRequest("POST", path, valid, gateway); err == nil || err.Type != "confidential_route_unsupported" {
			t.Fatalf("unsupported route accepted: %s", path)
		}
	}
	for _, body := range []string{`{"provider":true}`, `{"provider":{"min_privacy":3}}`, `[]`, `{`} {
		if err := validateConfidentialHostRequest("POST", "/v1/responses", []byte(body), gateway); err == nil {
			t.Fatalf("invalid body accepted: %s", body)
		}
	}
	for _, path := range []string{"/health", "/attestation", "/receipt-key", "/receipt-attestation", "/v1/models", "/v1/models/z-ai/glm-5.3"} {
		if err := validateConfidentialHostRequest("GET", path, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOrdinaryHostIgnoresForwardingHeaders(t *testing.T) {
	conn := newScriptedConn("POST /v1/chat/completions HTTP/1.1\r\nHost: api.trustedrouter.com\r\nX-Forwarded-Host: api.confidential.trustedrouter.com\r\nContent-Length: 2\r\n\r\n{}", nil)
	serveOne(context.Background(), conn, auth.New(nil), nil, nil, nil, nil, nil)
	if got := conn.writes.String(); !strings.Contains(got, "401 Unauthorized") || strings.Contains(got, "confidential_privacy_required") {
		t.Fatal(got)
	}
}

func TestDuplicateHostRejected(t *testing.T) {
	raw := "GET /health HTTP/1.1\r\nHost: api.trustedrouter.com\r\nhost: api.confidential.trustedrouter.com\r\n\r\n"
	_, _, _, _, _, _, err := readRequest(bufio.NewReader(strings.NewReader(raw)))
	if err == nil {
		t.Fatal("duplicate Host accepted")
	}
}

func TestConfidentialSNIAcrossRealTLSKeepalive(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	network, addr, config := startTLSServeOneLoopback(t, auth.New(nil), nil, "api.confidential.trustedrouter.com", "api.trustedrouter.com")
	conn, reader := dialServeOneTLS(t, network, addr, config)
	defer conn.Close()
	for index, request := range []string{
		"GET /health HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n",
		"POST /v1/responses HTTP/1.1\r\nHost: api.trustedrouter.com\r\nContent-Length: 2\r\n\r\n{}",
	} {
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 && response.StatusCode != 200 {
			t.Fatalf("health: %d %s", response.StatusCode, body)
		}
		if index == 1 && (response.StatusCode != 400 || !strings.Contains(string(body), "confidential_privacy_required")) {
			t.Fatalf("TLS SNI policy lost: %d %s", response.StatusCode, body)
		}
	}
}

func TestConfidentialPrivacySurvivesAPIsAndSubcall(t *testing.T) {
	var native adapter.AnthropicNativeRequest
	if err := json.Unmarshal([]byte(`{"provider":{"min_privacy":"confidential","only":["tinfoil"]}}`), &native); err != nil {
		t.Fatal(err)
	}
	request := adapter.MessagesToChatShim(&native)
	if err := trustedrouter.ValidateConfidentialRouting(request.Provider); err != nil {
		t.Fatal(err)
	}
	// The same cloning helper is used by synth, advisor, selector and mapreduce.
	child := cloneChatRequest(request)
	if child.Provider == request.Provider {
		t.Fatal("child shares mutable provider options")
	}
	if err := trustedrouter.ValidateConfidentialRouting(child.Provider); err != nil {
		t.Fatal(err)
	}
	child.Provider.MinPrivacy = "any"
	gateway := trustedrouter.New("https://must-not-authorize.invalid", "internal", nil)
	_, err := gateway.AuthorizeWithRoute(trustedrouter.WithConfidentialOnly(context.Background()), "", child, "chat.completions")
	if err == nil || !strings.Contains(err.Error(), "confidential") {
		t.Fatalf("child policy loss not caught: %v", err)
	}
}

func TestWebSearchRejectsExplicitPrivacy(t *testing.T) {
	for _, privacy := range []string{"confidential", "e2e", "e2ee", "zdr", "no_store"} {
		req := &types.OpenAIChatRequest{Provider: &types.ProviderRouting{MinPrivacy: privacy}}
		if err := validateResponsesWebSearchPrivacy(req); err == nil {
			t.Fatalf("search bypasses %s", privacy)
		}
	}
	zdr := true
	if validateResponsesWebSearchPrivacy(&types.OpenAIChatRequest{Provider: &types.ProviderRouting{ZDR: &zdr}}) == nil {
		t.Fatal("search bypasses ZDR")
	}
}
