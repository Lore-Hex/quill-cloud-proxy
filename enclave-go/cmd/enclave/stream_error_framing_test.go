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
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestExplicitProviderFailureCompletesHTTPFraming(t *testing.T) {
	for _, mode := range []string{"off", "on"} {
		for _, route := range []string{"chat/completions", "responses"} {
			t.Run(mode+"/"+route, func(t *testing.T) {
				t.Setenv("QUILL_KEEPALIVE", mode)
				var refunds, settlements atomic.Int32
				control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/internal/gateway/authorize":
						_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_fail","workspace_id":"ws_1","api_key_hash":"key_1","model":"anthropic/claude-3-5-sonnet","endpoint_id":"anthropic/claude-3-5-sonnet@anthropic/prepaid","provider":"anthropic","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
					case "/internal/gateway/refund":
						refunds.Add(1)
						_, _ = io.WriteString(w, `{"data":{"refunded":true}}`)
					case "/internal/gateway/settle":
						settlements.Add(1)
						_, _ = io.WriteString(w, `{"data":{}}`)
					default:
						t.Errorf("unexpected control-plane path %s", r.URL.Path)
						http.NotFound(w, r)
					}
				}))
				defer control.Close()
				gateway := trustedrouter.New(control.URL, "internal-token", control.Client())
				server, client := net.Pipe()
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(5 * time.Second))
				go serveOne(context.Background(), server, auth.New(nil), &failingStreamingLLM{}, nil, nil, gateway, nil)
				input := `"messages":[{"role":"user","content":"private input"}]`
				if route == "responses" {
					input = `"input":"private input"`
				}
				body := `{"model":"anthropic/claude-3-5-sonnet","stream":true,` + input + `}`
				if _, err := fmt.Fprintf(client, "POST /v1/%s HTTP/1.1\r\nHost: test.local\r\nAuthorization: Bearer test-key\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", route, len(body), body); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(client)
				response, err := http.ReadResponse(reader, nil)
				if err != nil {
					t.Fatal(err)
				}
				decoded, readErr := io.ReadAll(response.Body)
				response.Body.Close()
				if readErr != nil {
					t.Fatalf("explicit SSE failure has broken HTTP framing: %v; body=%s", readErr, decoded)
				}
				payload := string(decoded)
				if !strings.Contains(payload, `"type":"provider_error"`) || strings.Count(payload, "data: [DONE]") != 1 {
					t.Fatalf("expected one explicit terminal failure: %s", payload)
				}
				if route == "responses" && !strings.Contains(payload, "event: response.failed") {
					t.Fatalf("missing Responses failure event: %s", payload)
				}
				if strings.Contains(payload, "private input") || refunds.Load() != 1 || settlements.Load() != 0 {
					t.Fatalf("failure privacy/billing invariant violated: refunds=%d settlements=%d", refunds.Load(), settlements.Load())
				}
				if mode == "on" {
					writeAuthorizedGET(t, client, "test-key", "/not-found")
					next, _ := readHTTPResponseBody(t, reader)
					if next.StatusCode != http.StatusNotFound || next.Close {
						t.Fatalf("connection not reusable after explicit failure: status=%d close=%t", next.StatusCode, next.Close)
					}
				}
			})
		}
	}
}
