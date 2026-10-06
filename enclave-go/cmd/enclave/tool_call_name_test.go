package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestParseChatRequestRecoversToolCallName(t *testing.T) {
	req, err := parseChatRequest([]byte(`{"model":"test","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":null,"arguments":"{}"}},{"id":"call_2","type":"function","function":{"name":null,"arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","name":"get_weather","content":"sunny"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Messages[0].ToolCalls[0].Function.Name; got != "get_weather" {
		t.Errorf("name = %q, want get_weather", got)
	}
	if got := req.Messages[0].ToolCalls[1].Function.Name; got != "" {
		t.Errorf("unmatched name = %q, want empty", got)
	}
}

func TestAdvisorCustomToolHistoryUpstreamBody(t *testing.T) {
	req, err := parseChatRequest([]byte(`{"model":"trustedrouter/plato-4.0","messages":[{"role":"system","content":"Be helpful."},{"role":"user","content":"Weather?"},{"role":"assistant","tool_calls":[{"id":"call_1","type":"custom","custom":{"name":"get_weather","input":"Paris"}}]},{"role":"tool","tool_call_id":"call_1","content":"sunny"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	gateway, _, cleanup := newFusionGatewayRecorder(t)
	defer cleanup()
	var upstreamBody map[string]any
	provider := advisorTimeoutLLM(func(ctx context.Context, call *types.OpenAIChatRequest, out io.Writer) error {
		if call.Model != "xiaomi/mimo-v2.6-pro" {
			t.Errorf("first worker = %q, want xiaomi/mimo-v2.6-pro", call.Model)
		}
		body, err := adapter.ToAnthropic(call, call.Model)
		if err != nil {
			return err
		}
		// Use the real upstream request projection, including its JSON round trip,
		// at the fake provider boundary. No external provider is contacted.
		upstreamBody, err = llm.BuildOpenAICompatibleRequestShape(ctx, call, body, call.Model, true)
		if err != nil {
			return err
		}
		return writeAnthropicTextTestStream(out, call.Model, "sunny in Paris")
	})
	var out bytes.Buffer
	handled, err := maybeServeAdvisor(t.Context(), &out, provider, req, gateway, nil, "bearer", nil, "tool-history-test")
	if err != nil || !handled {
		t.Fatalf("handled=%t error=%v", handled, err)
	}
	encoded, err := json.Marshal(upstreamBody)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Messages []struct {
			ToolCalls []struct {
				Type     string                           `json:"type"`
				Function struct{ Name, Arguments string } `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Messages) < 3 || len(body.Messages[2].ToolCalls) != 1 {
		t.Fatalf("missing upstream tool call: %s", encoded)
	}
	call := body.Messages[2].ToolCalls[0]
	if call.Type != "function" || call.Function.Name != "get_weather" || call.Function.Arguments != `{"input":"Paris"}` {
		t.Fatalf("upstream messages[2].tool_calls[0] = %#v; body=%s", call, encoded)
	}
}

func TestAdvisorNamelessWorkerToolCallFallsBack(t *testing.T) {
	for _, name := range []string{"", " \t "} {
		t.Run("name="+name, func(t *testing.T) {
			gateway, _, cleanup := newFusionGatewayRecorder(t)
			defer cleanup()
			req := &types.OpenAIChatRequest{Model: trustedRouterPlato40Model, Messages: []types.OpenAIChatMessage{{Role: "user", Content: "Weather?"}}}
			provider := advisorTimeoutLLM(func(_ context.Context, call *types.OpenAIChatRequest, out io.Writer) error {
				switch call.Model {
				case "xiaomi/mimo-v2.6-pro":
					// Include usable text and another named call: every final call must have a name.
					if _, err := io.WriteString(out, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"first worker text\"}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"valid\",\"name\":\"get_weather\",\"input\":{}}}\n\n"); err != nil {
						return err
					}
					return writeAnthropicToolUseTestStream(out, name)
				case "deepseek/deepseek-v4.1-flash":
					return writeAnthropicTextTestStream(out, call.Model, "second worker answer")
				default:
					t.Errorf("unexpected worker %q", call.Model)
					return writeAnthropicTextTestStream(out, call.Model, "wrong worker")
				}
			})
			var out bytes.Buffer
			handled, err := maybeServeAdvisor(t.Context(), &out, provider, req, gateway, nil, "bearer", nil, "nameless-worker-test")
			if err != nil || !handled {
				t.Fatalf("handled=%t error=%v", handled, err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(&out), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			payload, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			var body struct {
				Choices []struct {
					Message struct {
						Content   string            `json:"content"`
						ToolCalls []json.RawMessage `json:"tool_calls"`
					} `json:"message"`
				} `json:"choices"`
			}
			if err := json.Unmarshal(payload, &body); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK || len(body.Choices) != 1 || body.Choices[0].Message.Content != "second worker answer" || len(body.Choices[0].Message.ToolCalls) != 0 {
				t.Fatalf("client response = %s", payload)
			}
		})
	}
}
