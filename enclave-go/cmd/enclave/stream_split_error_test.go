//go:build !cloud_aws

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestSplitProviderErrorRefundsInsteadOfSettlingAcrossAPIs(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	const good = "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2}}\n\n"
	for _, tc := range []struct {
		name, wire string
		failure    bool
	}{
		{"scalar error key", "data: {\ndata: \"error\"\ndata: :{\"code\":403,\"message\":\"refused\"}}\n", true},
		{"comment preserves key", "data: {\ndata: \"error\"\n: keepalive\ndata: :{\"code\":403,\"message\":\"refused\"}}\n", true},
		{"field preserves key", "data: {\ndata: \"error\"\nid: 42\ndata: :{\"code\":403,\"message\":\"refused\"}}\n", true},
		{"whitespace preserves key", "data: {\ndata: \"error\"" + strings.Repeat(" ", 100) + "\ndata: :{\"code\":403,\"message\":\"refused\"}}\n", true},
		{"scalar type key", "data: {\ndata: \"type\"\ndata: :\"error\"}\n", true},
		{"null is ordinary data", "data: {\ndata: \"error\"\ndata: : null}\n", false},
		{"healthy object resets tail", "data: {\"error\"\n" + strings.TrimSuffix(good, "\n") + "data: :{\"message\":\"refused\"}}\n", false},
		{"blank resets tail", "data: {\"error\"\n\ndata: :{\"message\":\"refused\"}}\n", false},
	} {
		for _, route := range []string{"chat.completions", "responses", "messages"} {
			t.Run(tc.name+"/"+route, func(t *testing.T) {
				provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
					io.WriteString(w, good+tc.wire+"\ndata: [DONE]\n\n")
				}))
				defer provider.Close()
				var refunds, settles atomic.Int32
				auth := &trustedrouter.Authorization{AuthorizationID: "split-error", Model: "model-a", Provider: "openai", EndpointID: "first", UsageType: "Credits"}
				gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					body := `{"data":{}}`
					switch r.URL.Path {
					case "/internal/gateway/authorize":
						encoded, _ := json.Marshal(map[string]any{"data": auth})
						body = string(encoded)
					case "/internal/gateway/refund":
						refunds.Add(1)
						body = `{"data":{"refunded":true}}`
					case "/internal/gateway/settle":
						settles.Add(1)
						body = `{"data":{"settled":true}}`
					default:
						t.Errorf("unexpected control request %s", r.URL.Path)
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})})
				client := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, w io.Writer) error {
					return llm.InvokeOpenAICompatibleStreaming(t.Context(), "openai", provider.URL, "test-key", &types.OpenAIChatRequest{Model: "model-a", Stream: true}, &types.AnthropicMessagesRequest{}, w, "model-a")
				}}
				var out bytes.Buffer
				serveErrorTestRoute(t.Context(), route, true, &out, client, gateway, auth, []llm.InvokeOptions{{Model: "model-a", Provider: "openai", EndpointID: "first"}})
				response, err := http.ReadResponse(bufio.NewReader(&out), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(body, []byte("partial")) {
					t.Fatalf("partial content lost: %s", body)
				}
				if tc.failure {
					if refunds.Load() != 1 || settles.Load() != 0 || !bytes.Contains(body, []byte(`"error":`)) || bytes.Contains(body, []byte("message_stop")) || bytes.Contains(body, []byte("response.completed")) {
						t.Fatalf("split failure settled/completed: refunds=%d settles=%d body=%s", refunds.Load(), settles.Load(), body)
					}
				} else if refunds.Load() != 0 || settles.Load() != 1 || bytes.Contains(body, []byte(`"error":{`)) {
					t.Fatalf("ordinary malformed chunks no longer skipped: refunds=%d settles=%d body=%s", refunds.Load(), settles.Load(), body)
				}
			})
		}
	}
}
