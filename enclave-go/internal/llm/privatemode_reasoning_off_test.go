package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestPrivatemodeGLMReasoningOffReachesEncryptedTransport(t *testing.T) {
	for _, model := range []string{"glm-5.3", "glm-5.3-flash"} {
		for _, control := range []string{"top-level", "nested", "disabled", "native-disabled"} {
			t.Run(model+"/"+control, func(t *testing.T) {
				defer ConfigurePrivatemode(nil)
				zero := 0.0
				req := &qtypes.OpenAIChatRequest{Model: "z-ai/" + model}
				body := &qtypes.AnthropicMessagesRequest{MaxTokens: 16, Temperature: &zero,
					Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "synthetic"}}}
				switch control {
				case "top-level":
					req.ReasoningEffort = "none"
				case "nested":
					req.Reasoning = map[string]any{"effort": "none"}
				case "disabled":
					req.Reasoning = map[string]any{"enabled": false}
				case "native-disabled":
					body.NativeContent = true
					body.Thinking = map[string]any{"type": "disabled"}
				}
				calls := 0
				ConfigurePrivatemode(&http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.URL.String() != "https://privatemode.internal:18489/v1/chat/completions" {
						t.Fatal("request escaped the attested transport")
					}
					var wire map[string]any
					if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
						t.Fatal(err)
					}
					if wire["model"] != model || wire["reasoning_effort"] != "none" || wire["temperature"] != float64(0) {
						t.Fatal("explicit off or temperature was not preserved")
					}
					if wire["thinking"] != nil || wire["reasoning"] != nil {
						t.Fatal("duplicate reasoning controls reached upstream")
					}
					if salt, _ := wire["cache_salt"].(string); len(salt) != 64 {
						t.Fatal("workspace cache isolation missing")
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}},
						Body: io.NopCloser(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n" +
							"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2,\"total_tokens\":12}}\n\ndata: [DONE]\n\n"))}, nil
				})})
				err := newOpenAICompatible("privatemode", "synthetic-key").InvokeStreaming(t.Context(), req, body,
					io.Discard, InvokeOptions{Provider: "privatemode", UpstreamModel: model, ProviderCacheScope: "synthetic-workspace"})
				if err != nil || calls != 1 {
					t.Fatalf("reasoning off rejected or retried: calls=%d err=%v", calls, err)
				}
			})
		}
	}
}

func TestPrivatemodeGLMStillRejectsUnrepresentableReasoning(t *testing.T) {
	for _, model := range []string{"glm-5.3", "glm-5.3-flash", "gpt-oss-120b"} {
		for _, reasoning := range []map[string]any{{"effort": "medium"}, {"max_tokens": 128}, {"enabled": true, "effort": "none"}} {
			if model == "gpt-oss-120b" && reasoning["effort"] == "medium" {
				continue
			}
			err := preparePrivatemodeWire(&qtypes.OpenAIChatRequest{Reasoning: reasoning}, nil,
				&openAICompatibleRequest{Model: model}, "scope")
			if status, ok := HTTPStatusFromError(err); !ok || status != 400 {
				t.Fatalf("model=%s unsupported control accepted: %v", model, err)
			}
		}
	}
	for _, model := range []string{"gpt-oss-120b", "glm-latest", "glm-future"} {
		for _, reasoning := range []map[string]any{{"effort": "none"}, {"enabled": false}} {
			if err := preparePrivatemodeWire(&qtypes.OpenAIChatRequest{Reasoning: reasoning}, nil,
				&openAICompatibleRequest{Model: model}, "scope"); err == nil {
				t.Fatalf("reasoning off accepted for unqualified model %s", model)
			}
		}
	}
}
