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
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type decisionMetadataLLM struct {
	calls        atomic.Int32
	outputTokens int
}

func (f *decisionMetadataLLM) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	f.calls.Add(1)
	_, err := fmt.Fprintf(out, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"{\\\"answer\\\":\\\"billing\\\"}\"}}\n\n"+
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":167,\"output_tokens\":%d},\"trustedrouter_decision\":{\"answer\":\"billing\",\"confidence\":0.98,\"probabilities\":{\"billing\":0.99,\"private-decision-label\":0.01}}}\n\n"+
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", f.outputTokens)
	return err
}

func TestChatDecisionMetadataReturnedButExcludedFromControlPlane(t *testing.T) {
	for _, outputTokens := range []int{0, 6} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("output=%d/stream=%t", outputTokens, stream), func(t *testing.T) {
				var authorizations, settlements atomic.Int32
				control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					for _, forbidden := range []string{"private-decision-label", "confidence", "probabilities", "trustedrouter_decision"} {
						if strings.Contains(string(body), forbidden) {
							t.Errorf("decision data leaked to control plane: %s", forbidden)
						}
					}
					switch r.URL.Path {
					case "/internal/gateway/authorize":
						authorizations.Add(1)
						_, _ = io.WriteString(w, `{"data":{"authorization_id":"auth_decision","workspace_id":"ws_1","api_key_hash":"key_1","model":"neurometric/structured-decisions","endpoint_id":"neurometric/structured-decisions@neurometric/prepaid","provider":"neurometric","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`)
					case "/internal/gateway/settle":
						settlements.Add(1)
						var payload map[string]any
						if err := json.Unmarshal(body, &payload); err != nil {
							t.Error(err)
						}
						if payload["actual_input_tokens"] != float64(167) || payload["actual_output_tokens"] != float64(outputTokens) || payload["usage_estimated"] == true {
							t.Errorf("changed billable usage: %s", body)
						}
						_, _ = io.WriteString(w, `{"data":{"settled":true,"generation_id":"gen_decision","cost_microdollars":5,"model":"neurometric/structured-decisions","provider":"neurometric","region":"us-central1"}}`)
					default:
						t.Errorf("unexpected operation: %s", r.URL.Path)
						w.WriteHeader(500)
					}
				}))
				defer control.Close()
				gateway := trustedrouter.New(control.URL, "internal-test", control.Client())
				server, client := net.Pipe()
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(10 * time.Second))
				streamer := &decisionMetadataLLM{outputTokens: outputTokens}
				done := make(chan struct{})
				go func() {
					defer close(done)
					serveOne(context.Background(), server, auth.New(nil), streamer, nil, nil, gateway, nil)
				}()
				body := fmt.Sprintf(`{"model":"neurometric/structured-decisions","messages":[{"role":"user","content":"synthetic ticket"}],"stream":%t,"stream_options":{"include_usage":true}}`, stream)
				_, err := fmt.Fprintf(client, "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer test-key\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
				if err != nil {
					t.Fatal(err)
				}
				resp, responseBody := readHTTPResponseBody(t, bufio.NewReader(client))
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Fatal("request did not complete")
				}
				if resp.StatusCode != 200 || !strings.Contains(responseBody, `"confidence":0.98`) || !strings.Contains(responseBody, "private-decision-label") || !strings.Contains(responseBody, `"cost_microdollars":5`) {
					t.Fatalf("response lost answer metadata or cost: %d %s", resp.StatusCode, responseBody)
				}
				if authorizations.Load() != 1 || settlements.Load() != 1 || streamer.calls.Load() != 1 {
					t.Fatalf("authorize=%d settle=%d inference=%d", authorizations.Load(), settlements.Load(), streamer.calls.Load())
				}
				var usage map[string]any
				if stream {
					for _, line := range strings.Split(responseBody, "\n") {
						if !strings.HasPrefix(line, "data: {") {
							continue
						}
						var chunk map[string]any
						if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &chunk); err != nil {
							t.Fatal(err)
						}
						if u, ok := chunk["usage"].(map[string]any); ok {
							usage = u
						}
					}
				} else {
					var response map[string]any
					if err := json.Unmarshal([]byte(responseBody), &response); err != nil {
						t.Fatal(err)
					}
					usage, _ = response["usage"].(map[string]any)
				}
				if usage["prompt_tokens"] != float64(167) || usage["completion_tokens"] != float64(outputTokens) || usage["total_tokens"] != float64(167+outputTokens) {
					t.Fatalf("public usage changed: %#v", usage)
				}
			})
		}
	}
}
