//go:build cloud_aws

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestAWSUserModelFailsBeforeAuthorizeOnEveryInferenceRoute(t *testing.T) {
	var authorizeCalls atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/resolve-custom-model":
			_, _ = io.WriteString(w, `{"data":{"custom_model":{"id":"trustedrouter/user-demo","kind":"user_provided","user_model_kind":"machine","owner_workspace_id":"owner-ws","endpoint_url":"https://owner.example/v1","upstream_model_id":"owner-private","secret_namespace":"user_model","signing_encrypted_secret":{"algorithm":"TR-BYOK-ENVELOPE-AES-256-GCM-V2"},"signing_secret_purpose":"user_model_signing","connect_timeout_seconds":10,"first_byte_timeout_seconds":30,"idle_timeout_seconds":60,"total_timeout_seconds":300}}}`)
		case "/internal/gateway/authorize":
			authorizeCalls.Add(1)
			t.Error("AWS plane error must happen before authorize")
		case "/internal/gateway/validate":
			// Request-observer attribution runs independently after the public
			// response; it is metadata-only and creates no billing hold.
			_, _ = io.WriteString(w, `{"data":{"valid":true,"workspace_id":"caller-ws","api_key_hash":"caller-key"}}`)
		default:
			t.Errorf("unexpected control-plane path %s", r.URL.Path)
		}
	}))
	defer controlPlane.Close()
	gateway := trustedrouter.New(controlPlane.URL, "internal", controlPlane.Client())

	for _, test := range []struct {
		path   string
		header string
		body   string
	}{
		{path: "/v1/chat/completions", header: "Authorization: Bearer caller-key", body: `{"model":"trustedrouter/user-demo","messages":[{"role":"user","content":"private prompt"}]}`},
		{path: "/v1/responses", header: "Authorization: Bearer caller-key", body: `{"model":"trustedrouter/user-demo","input":"private prompt"}`},
		{path: "/v1/messages", header: "x-api-key: caller-key", body: `{"model":"trustedrouter/user-demo","max_tokens":32,"messages":[{"role":"user","content":"private prompt"}]}`},
	} {
		t.Run(test.path, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			go serveOne(
				context.Background(), serverConn, auth.New(nil), &panicStreamingLLM{t: t},
				nil, nil, gateway, nil,
			)
			_, _ = fmt.Fprintf(clientConn, "POST %s HTTP/1.1\r\n%s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", test.path, test.header, len(test.body), test.body)
			response, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			payload, _ := io.ReadAll(response.Body)
			response.Body.Close()
			clientConn.Close()
			if response.StatusCode != http.StatusServiceUnavailable ||
				!strings.Contains(string(payload), `"type":"user_model_unavailable_on_plane"`) ||
				!strings.Contains(string(payload), "User-provided models are not served from this region yet") {
				t.Fatalf("status=%d body=%s", response.StatusCode, payload)
			}
		})
	}
	if authorizeCalls.Load() != 0 {
		t.Fatalf("authorize calls = %d", authorizeCalls.Load())
	}
}
