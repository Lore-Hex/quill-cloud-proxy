package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const abliterateTestModel = "abliterate/abliterate-0.3-fast"

type missingUsageLLM struct{}

func (*missingUsageLLM) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	_, err := io.WriteString(out, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\",\"content\":[]}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello world\"}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	return err
}

func abliterateTestAuthorization() *trustedrouter.Authorization {
	auth := costReportingAuthorization()
	auth.Model, auth.Provider = abliterateTestModel, "abliterate"
	auth.EstimatedCostMicrodollars, auth.CapMicro = 100, 100
	return auth
}

func TestAbliterateEstimatedBillingAcrossResponseFormats(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	for _, route := range []string{"chat.completions", "responses", "messages"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", route, stream), func(t *testing.T) {
				auth := abliterateTestAuthorization()
				settles := 0
				var billed struct {
					Input     int  `json:"actual_input_tokens"`
					Output    int  `json:"actual_output_tokens"`
					Estimated bool `json:"usage_estimated"`
				}
				gateway := trustedrouter.New("http://127.0.0.1:18080", "test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					body := `{"data":{"cost_microdollars":29,"disposition":"finalized"}}`
					switch r.URL.Path {
					case "/internal/gateway/authorize":
						encoded, _ := json.Marshal(map[string]any{"data": auth})
						body = string(encoded)
					case "/internal/gateway/settle":
						settles++
						if err := json.NewDecoder(r.Body).Decode(&billed); err != nil {
							t.Fatal(err)
						}
					default:
						t.Fatalf("unexpected billing path: %s", r.URL.Path)
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})})
				maxTokens := 32
				req := &types.OpenAIChatRequest{Model: abliterateTestModel, MaxTokens: &maxTokens, Stream: stream, StreamOptions: &types.ChatStreamOptions{IncludeUsage: true}, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}}}
				options := []llm.InvokeOptions{{Model: req.Model, Provider: "abliterate", EndpointID: "served"}}
				var out bytes.Buffer
				provider := &missingUsageLLM{}
				if route == "messages" {
					body := []byte(fmt.Sprintf(`{"model":%q,"max_tokens":32,"stream":%t,"messages":[{"role":"user","content":"hi"}]}`, req.Model, stream))
					serveMessages(context.Background(), &out, provider, body, gateway, nil, "test-key", "", "estimated-billing", requestAttributionHeaders{})
				} else if stream {
					serveStreaming(context.Background(), &out, provider, req, &types.AnthropicMessagesRequest{}, options, gateway, auth, nil, time.Now(), nil, route, "estimated-billing", req.Model)
				} else if route == "responses" {
					serveResponsesNonStreaming(context.Background(), &out, provider, req, &types.AnthropicMessagesRequest{}, options, gateway, auth, nil, time.Now(), nil, "estimated-billing", req.Model)
				} else {
					serveChatNonStreaming(context.Background(), &out, provider, req, &types.AnthropicMessagesRequest{}, options, gateway, auth, nil, time.Now(), nil, "estimated-billing", req.Model)
				}
				wantInput := 2 * trustedrouter.EstimateInputTokens(req)
				wantOutput := 2 * trustedrouter.EstimateOutputTokens("Hello world")
				if settles != 1 || billed.Input != wantInput || billed.Output != wantOutput || !billed.Estimated {
					t.Fatalf("settles=%d billed=%+v want estimated %d/%d", settles, billed, wantInput, wantOutput)
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
				if response.StatusCode != 200 {
					t.Fatalf("%d %s", response.StatusCode, body)
				}
				// Inspect the terminal payload without assuming how many deltas the provider sends.
				var payload map[string]any
				if stream {
					for _, line := range strings.Split(string(body), "\n") {
						if !strings.HasPrefix(line, "data: {") {
							continue
						}
						var event map[string]any
						if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
							t.Fatal(err)
						}
						if event["type"] == "response.completed" {
							event = event["response"].(map[string]any)
						}
						if event["usage"] != nil {
							payload = event
						}
					}
				} else if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatal(err)
				}
				usage, _ := payload["usage"].(map[string]any)
				inputKey, outputKey := "input_tokens", "output_tokens"
				if route == "chat.completions" {
					inputKey, outputKey = "prompt_tokens", "completion_tokens"
				}
				if usage[inputKey] != float64(wantInput) || usage[outputKey] != float64(wantOutput) || usage["usage_estimated"] != true {
					t.Fatalf("public usage differs from billing or hides estimate: %s", body)
				}
			})
		}
	}
}
