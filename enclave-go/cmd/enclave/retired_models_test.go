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
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestRetiredFallbackListsAndManagementPaths(t *testing.T) {
	for _, id := range []string{"tr-custom-model/demo", "tr-user-model/demo", "trustedrouter/user-demo", "nyte/user-demo", " TR-CUSTOM-MODEL/demo "} {
		if !retiredModelRequest(&types.OpenAIChatRequest{Model: "openai/gpt-4.1", Models: []string{"deepseek/deepseek-chat", id}}) {
			t.Fatalf("retired fallback accepted: %q", id)
		}
	}
	for _, path := range []string{"/custom-models", "/v1/custom-models/demo", "/v1/user-models", "/v1/user-models/demo/rotate-secrets", "/v1/internal/gateway/resolve-custom-model", "/models/user-provided"} {
		if !retiredModelManagementPath(path) {
			t.Fatalf("management path remains reachable: %q", path)
		}
	}
	for _, path := range []string{"/v1/models", "/v1/keys", "/health"} {
		if retiredModelManagementPath(path) {
			t.Fatalf("ordinary path blocked: %q", path)
		}
	}
}

func TestRetiredModelsFailBeforeAuthorizeOnEveryInferenceRoute(t *testing.T) {
	var authorizeCalls atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/gateway/authorize":
			authorizeCalls.Add(1)
			t.Error("retirement must be enforced before authorize")
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

	for _, model := range []string{"trustedrouter/user-demo", "tr-user-model/demo", "tr-custom-model/demo", "nyte/user-demo"} {
		for _, stream := range []bool{true, false} {
			for _, test := range []struct {
				path   string
				header string
				body   string
			}{
				{path: "/v1/chat/completions", header: "Authorization: Bearer caller-key", body: `{"model":"trustedrouter/user-demo","messages":[{"role":"user","content":"private prompt"}]}`},
				{path: "/v1/responses", header: "Authorization: Bearer caller-key", body: `{"model":"trustedrouter/user-demo","input":"private prompt"}`},
				{path: "/v1/messages", header: "x-api-key: caller-key", body: `{"model":"trustedrouter/user-demo","max_tokens":32,"messages":[{"role":"user","content":"private prompt"}]}`},
			} {
				t.Run(model+test.path+fmt.Sprint(stream), func(t *testing.T) {
					test.body = strings.ReplaceAll(test.body, "trustedrouter/user-demo", model)
					test.body = strings.TrimSuffix(test.body, "}") + fmt.Sprintf(",\"stream\":%t}", stream)
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
					if response.StatusCode != http.StatusGone || !strings.Contains(string(payload), "have been retired") {
						t.Fatalf("status=%d body=%s", response.StatusCode, payload)
					}
				})
			}
		}
	}
	if authorizeCalls.Load() != 0 {
		t.Fatalf("authorize calls = %d", authorizeCalls.Load())
	}
}
