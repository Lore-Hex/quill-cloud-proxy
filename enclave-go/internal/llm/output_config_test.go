//go:build llm_multi

package llm

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestOutputConfigEffortReachesClaudeTransports(t *testing.T) {
	for _, transport := range []string{"anthropic", "byok", "vertex"} {
		for _, native := range []bool{false, true} {
			for _, stream := range []bool{false, true} {
				for _, effort := range []string{"low", "medium", "high", "xhigh", "max"} {
					t.Run(fmt.Sprintf("%s/native=%t/stream=%t/%s", transport, native, stream, effort), func(t *testing.T) {
						payload := []byte(fmt.Sprintf(`{"model":"anthropic/claude-opus-5.5","messages":[{"role":"user","content":"Reply OK"}],"output_config":{"effort":%q},"thinking":{"type":"adaptive"},"max_tokens":4096,"stream":%t}`, effort, stream))
						var req qtypes.OpenAIChatRequest
						if err := json.Unmarshal(payload, &req); err != nil {
							t.Fatal(err)
						}
						var body *qtypes.AnthropicMessagesRequest
						var err error
						if native {
							var request adapter.AnthropicNativeRequest
							if err := json.Unmarshal(payload, &request); err != nil {
								t.Fatal(err)
							}
							body, err = adapter.MessagesToAnthropic(&request)
						} else {
							var raw map[string]json.RawMessage
							if err := json.Unmarshal(payload, &raw); err != nil {
								t.Fatal(err)
							}
							validation, err := adapter.ValidateChatRequestFields(raw)
							if err != nil {
								t.Fatal(err)
							}
							req.Reasoning = validation.ReasoningAlias
							body, err = adapter.ToAnthropic(&req, req.Model)
							if err != nil {
								t.Fatal(err)
							}
						}
						if err != nil {
							t.Fatal(err)
						}
						before, err := json.Marshal(body)
						if err != nil {
							t.Fatal(err)
						}
						calls := 0
						httpc := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
							calls++
							var wire map[string]any
							if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
								t.Fatal(err)
							}
							if !reflect.DeepEqual(wire["output_config"], map[string]any{"effort": effort}) || !reflect.DeepEqual(wire["thinking"], map[string]any{"type": "adaptive"}) {
								t.Fatalf("lost native effort: %#v", wire)
							}
							if wire["reasoning"] != nil || wire["reasoning_effort"] != nil || wire["max_tokens"] != float64(4096) {
								t.Fatalf("leaked aliases or changed explicit cap: %#v", wire)
							}
							return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")), Header: make(http.Header)}, nil
						})}
						switch transport {
						case "byok":
							err = invokeAnthropicBYOKStreamingWithClient(t.Context(), httpc, &req, body, io.Discard, "test-key", "claude-opus-5-5")
						case "anthropic":
							client := &anthropicClient{provider: "anthropic", url: anthropicURL, apiKey: "test-key", httpc: httpc}
							err = client.InvokeStreaming(t.Context(), &req, body, io.Discard, InvokeOptions{UpstreamModel: "claude-opus-5-5"})
						case "vertex":
							client := &gcpClient{projectID: "test", region: "global", httpc: httpc, token: "test-token", tokenExp: time.Now().Add(time.Hour)}
							err = client.InvokeStreaming(t.Context(), &req, body, io.Discard, InvokeOptions{UpstreamModel: "claude-opus-5-5"})
						}
						if err != nil || calls != 1 {
							t.Fatalf("calls=%d error=%v", calls, err)
						}
						after, err := json.Marshal(body)
						if err != nil || string(before) != string(after) {
							t.Fatal("mutated the shared fallback body")
						}
					})
				}
			}
		}
	}
}
