package main

import (
	"bufio"
	"context"
	"encoding/json"
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

func TestServeChatStorePolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		store  string
		stream bool
		status int
		route  string
	}{
		{"nonstream", "false", false, 200, "/v1/chat/completions"},
		{"stream", "false", true, 200, "/v1/chat/completions"},
		{"null-default", "null", false, 200, "/v1/chat/completions"},
		{"storage-unsupported", "true", false, 501, "/v1/chat/completions"},
		{"storage-unsupported-stream", "true", true, 501, "/v1/chat/completions"},
		{"malformed", `"false"`, true, 400, "/v1/chat/completions"},
		{"responses-storage-unsupported", "true", false, 501, "/v1/responses"},
		{"responses-storage-unsupported-stream", "true", true, 501, "/v1/responses"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var authorizations, settlements, unexpected atomic.Int32
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), "private-chat-content") || strings.Contains(string(body), "sk-private-test-bearer") {
					t.Error("control plane received prompt or raw credential")
				}
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					authorizations.Add(1)
					_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_chat_store","workspace_id":"ws_1","api_key_hash":"key_1","model":"openai/gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
				case "/internal/gateway/settle":
					settlements.Add(1)
					_, _ = io.WriteString(w, `{"data":{"settled":true,"generation_id":"gen_store","cost_microdollars":12,"model":"openai/gpt-4o-mini","provider":"openai","region":"us-central1"}}`)
				case "/internal/gateway/validate":
					var payload struct {
						Rejection struct {
							Status    int    `json:"status"`
							Parameter string `json:"parameter"`
							RequestID string `json:"request_id"`
						} `json:"contract_rejection"`
					}
					if err := json.Unmarshal(body, &payload); err != nil {
						t.Error(err)
					}
					if payload.Rejection.Status != tc.status || payload.Rejection.Parameter != "store" || !strings.HasPrefix(payload.Rejection.RequestID, "rlog_") {
						t.Errorf("missing rejection metadata: %s", body)
					}
					_, _ = io.WriteString(w, `{"data":{"workspace_id":"ws_1","api_key_hash":"key_1"}}`)
				default:
					unexpected.Add(1)
					w.WriteHeader(500)
				}
			}))
			defer control.Close()
			gateway := trustedrouter.New(control.URL, "internal-test", control.Client())
			server, client := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			streamer := &fakeStreamingLLM{}
			done := make(chan struct{})
			go func() {
				defer close(done)
				serveOne(context.Background(), server, auth.New(nil), streamer, nil, nil, gateway, nil)
			}()
			body := fmt.Sprintf(`{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"private-chat-content"}],"max_tokens":32,"store":%s,"stream":%t,"stream_options":{"include_usage":true}}`, tc.store, tc.stream)
			if tc.route == "/v1/responses" {
				body = fmt.Sprintf(`{"model":"openai/gpt-4o-mini","input":"private-chat-content","store":%s,"stream":%t}`, tc.store, tc.stream)
			}
			_, err := fmt.Fprintf(client, "POST %s HTTP/1.1\r\nAuthorization: Bearer sk-private-test-bearer\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", tc.route, len(body), body)
			if err != nil {
				t.Fatal(err)
			}
			resp, responseBody := readHTTPResponseBody(t, bufio.NewReader(client))
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not complete")
			}
			if resp.StatusCode != tc.status {
				t.Fatalf("status=%d, want %d; body=%s", resp.StatusCode, tc.status, responseBody)
			}
			if unexpected.Load() != 0 {
				t.Fatal("unexpected billing/control operation")
			}
			if tc.status != 200 {
				if authorizations.Load() != 0 || settlements.Load() != 0 || streamer.request != nil {
					t.Fatal("rejected store policy invoked a provider or billed")
				}
				var payload struct{ Error struct{ Param string } }
				wantParam := "store"
				if tc.route == "/v1/responses" {
					wantParam = "store=true"
				}
				if err := json.Unmarshal([]byte(responseBody), &payload); err != nil || payload.Error.Param != wantParam {
					t.Fatalf("missing store error: %s", responseBody)
				}
				return
			}
			if authorizations.Load() != 1 || settlements.Load() != 1 || streamer.request == nil {
				t.Fatalf("authorizations=%d settlements=%d provider-called=%t", authorizations.Load(), settlements.Load(), streamer.request != nil)
			}
			if tc.stream {
				if !strings.Contains(responseBody, "Hello") || strings.Count(responseBody, "data: [DONE]") != 1 {
					t.Fatalf("incomplete stream: %s", responseBody)
				}
			} else if !strings.Contains(responseBody, "Hello world") {
				t.Fatalf("missing completion: %s", responseBody)
			}
		})
	}
}
