package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/bedrock"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/sse"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestSettlementWaitsForUpstreamSuccess(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	for _, route := range []string{"messages", "chat.completions", "responses"} {
		for _, ending := range []string{"error", "stop", "EOF"} {
			if ending == "EOF" && route != "messages" {
				continue
			}
			t.Run(route+"/"+ending, func(t *testing.T) {
				auth := costReportingAuthorization()
				var settlements, refunds atomic.Int32
				gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					body := `{"data":{"cost_microdollars":19,"disposition":"finalized"}}`
					switch r.URL.Path {
					case "/internal/gateway/authorize":
						encoded, _ := json.Marshal(map[string]any{"data": auth})
						body = string(encoded)
					case "/internal/gateway/settle":
						settlements.Add(1)
					case "/internal/gateway/refund":
						refunds.Add(1)
					default:
						t.Errorf("unexpected control request %s", r.URL.Path)
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})})
				provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, w io.Writer) error {
					wire := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"provider-msg\",\"usage\":{\"input_tokens\":5}}}\n\n" +
						"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n" +
						"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n"
					if ending == "error" {
						wire += "event: error\ndata: {\"error\":{\"code\":403,\"message\":\"refused\"}}\n\n"
					}
					if ending == "stop" {
						wire += "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
					}
					reader := sse.NewReader(strings.NewReader(wire), 1<<20)
					for reader.Next() {
						if _, err := io.WriteString(w, reader.Event().Raw); err != nil {
							return err
						}
					}
					return reader.Err()
				}}
				var out bytes.Buffer
				if route == "messages" {
					serveErrorTestRoute(t.Context(), route, true, &out, provider, gateway, auth, nil)
				} else {
					req := &types.OpenAIChatRequest{Model: "model-a", Stream: true, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}}, StreamOptions: &types.ChatStreamOptions{IncludeUsage: true}}
					serveStreaming(t.Context(), &out, provider, req, &types.AnthropicMessagesRequest{}, nil, gateway, auth, nil, time.Now(), nil, route, "upstream-success", "model-a")
				}
				response, err := http.ReadResponse(bufio.NewReader(&out), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != 200 || !bytes.Contains(body, []byte("partial")) {
					t.Fatalf("missing content: status=%d body=%s", response.StatusCode, body)
				}
				if ending == "error" {
					if settlements.Load() != 0 || refunds.Load() != 1 || !bytes.Contains(body, []byte(`"status":403`)) || bytes.Contains(body, []byte(`"cost_microdollars"`)) || bytes.Contains(body, []byte("event: message_delta")) || bytes.Contains(body, []byte(`"finish_reason":"stop"`)) || bytes.Contains(body, []byte("event: response.completed")) {
						t.Fatalf("failed stream billed or completed: settles=%d refunds=%d body=%s", settlements.Load(), refunds.Load(), body)
					}
				} else {
					if settlements.Load() != 1 || refunds.Load() != 0 || !bytes.Contains(body, []byte(`"cost_microdollars":19`)) {
						t.Fatalf("success missing settled usage: settles=%d refunds=%d body=%s", settlements.Load(), refunds.Load(), body)
					}
				}
			})
		}
	}
}

// Provider translators' exact framing/error results are covered by
// llm.TestProviderSplitErrorAfterContent. Exercise each transport's
// resulting error through the real gateway refund/settlement path here.
func TestSplitErrorBilling(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	for _, framing := range []string{"line", "spec", "bedrock"} {
		for _, route := range []string{"messages", "chat.completions", "responses"} {
			t.Run(framing+"/"+route, func(t *testing.T) {
				auth := costReportingAuthorization()
				auth.HidePublicMetadata = true
				var settles, refunds atomic.Int32
				gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					body := `{"data":{}}`
					switch r.URL.Path {
					case "/internal/gateway/authorize":
						encoded, _ := json.Marshal(map[string]any{"data": auth})
						body = string(encoded)
					case "/internal/gateway/refund":
						refunds.Add(1)
					case "/internal/gateway/settle":
						settles.Add(1)
					default:
						t.Errorf("unexpected control request %s", r.URL.Path)
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})})
				provider := &scriptedProviderStreamClient{invoke: func(_ llm.InvokeOptions, w io.Writer) error {
					if _, err := io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n"); err != nil {
						return err
					}
					if framing == "bedrock" {
						return bedrock.RelayEvent([]byte("{\"error\":\n{\"code\":403,\"message\":\"refused\"}}"), w)
					}
					wire := "data: {\"error\":\ndata: {\"code\":403,\"message\":\"refused\"}}\n\n"
					r := sse.NewReader(strings.NewReader(wire), 1024)
					if framing == "line" {
						r = sse.NewLineReader(strings.NewReader(wire), 1024)
					}
					for r.Next() {
						if _, err := io.WriteString(w, r.Event().Raw); err != nil {
							return err
						}
					}
					return r.Err()
				}}
				var out bytes.Buffer
				serveErrorTestRoute(t.Context(), route, true, &out, provider, gateway, auth, nil)
				response, err := http.ReadResponse(bufio.NewReader(&out), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				status := `"status":403`
				if framing == "line" {
					status = `"status":502`
				}
				if response.StatusCode != 200 || settles.Load() != 0 || refunds.Load() != 1 || !bytes.Contains(body, []byte("partial")) || !bytes.Contains(body, []byte(status)) || bytes.Contains(body, []byte("refused")) || bytes.Contains(body, []byte("event: message_stop")) || bytes.Contains(body, []byte("event: response.completed")) {
					t.Fatalf("split error billing/framing: status=%d settles=%d refunds=%d body=%s", response.StatusCode, settles.Load(), refunds.Load(), body)
				}
			})
		}
	}
}
