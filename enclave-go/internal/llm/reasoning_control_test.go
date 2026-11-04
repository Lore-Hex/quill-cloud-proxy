package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestHybridReasoningNativeWire(t *testing.T) {
	for _, provider := range []string{"zai", "deepseek", "kimi"} {
		for _, enabled := range []bool{false, true} {
			mode := "disabled"
			if enabled {
				mode = "enabled"
			}
			t.Run(provider+"/"+mode, func(t *testing.T) {
				zero := 0.0
				model := map[string]string{"zai": "glm-5.2", "deepseek": "deepseek-v4-flash", "kimi": "kimi-k2.6"}[provider]
				req := &qtypes.OpenAIChatRequest{Model: model, Reasoning: map[string]any{"enabled": enabled}, ReasoningEffort: "high"}
				body := &qtypes.AnthropicMessagesRequest{
					Temperature: &zero, Thinking: map[string]any{"type": "enabled", "budget_tokens": 4096},
					Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Hello"}},
				}
				calls := 0
				httpc := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					var wire map[string]any
					if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
						t.Fatal(err)
					}
					thinking, ok := wire["thinking"].(map[string]any)
					if !ok || thinking["type"] != mode || len(thinking) != 1 {
						t.Fatalf("thinking = %#v", wire["thinking"])
					}
					if _, present := wire["reasoning"]; present {
						t.Fatal("generic reasoning leaked to native endpoint")
					}
					if !enabled && wire["reasoning_effort"] != nil {
						t.Fatal("Off still has an enabling effort")
					}
					if provider != "kimi" && wire["temperature"] != float64(0) {
						t.Fatalf("temperature zero lost: %#v", wire["temperature"])
					}
					if provider == "kimi" && wire["temperature"] != nil {
						t.Fatal("Kimi fixed sampling contract changed")
					}
					if r.Header.Get("Authorization") != "Bearer test-key" || r.URL.Path != "/v1/chat/completions" {
						t.Fatal("request transport changed")
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"))}, nil
				})}
				err := invokeOpenAICompatibleStreamingWithClientOptions(t.Context(), httpc, provider, "https://provider.test/v1", "test-key", req, body, io.Discard, model, openAICompatibleInvocationOptions{})
				if err != nil || calls != 1 {
					t.Fatalf("calls=%d error=%v", calls, err)
				}
			})
		}
	}
}

func TestCerebrasNestedReasoningUsesNativeEffort(t *testing.T) {
	for _, model := range []string{"gpt-oss-120b", "qwen-3.8-27b"} {
		t.Run(model, func(t *testing.T) {
			reasoning := map[string]any{"effort": "low"}
			req := &qtypes.OpenAIChatRequest{Model: model, Reasoning: reasoning}
			body := &qtypes.AnthropicMessagesRequest{
				Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Hello"}},
				Thinking: map[string]any{"type": "enabled", "budget_tokens": 4096},
			}
			calls := 0
			httpc := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				var wire map[string]any
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Fatal(err)
				}
				if wire["reasoning_effort"] != "low" || wire["reasoning"] != nil || wire["thinking"] != nil {
					t.Fatalf("unsupported reasoning wire: effort=%v reasoning=%v thinking=%v", wire["reasoning_effort"], wire["reasoning"], wire["thinking"])
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"))}, nil
			})}
			err := invokeOpenAICompatibleStreamingWithClientOptions(t.Context(), httpc, "cerebras", "https://provider.test/v1", "test-key", req, body, io.Discard, model, openAICompatibleInvocationOptions{})
			if err != nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			if reasoning["effort"] != "low" || len(reasoning) != 1 {
				t.Fatal("mutated caller reasoning")
			}
		})
	}
}

func TestHybridReasoningLeavesUnspecifiedAndOtherProvidersAlone(t *testing.T) {
	for _, provider := range []string{"zai", "deepseek", "kimi", "openai", "together", "azure"} {
		for _, reasoning := range []any{nil, map[string]any{"effort": "low"}, map[string]any{"enabled": "false"}} {
			wire := openAICompatibleRequest{Thinking: "sentinel"}
			applyHybridReasoningControl(provider, &qtypes.OpenAIChatRequest{Reasoning: reasoning}, &wire)
			if wire.Thinking != "sentinel" {
				t.Fatalf("%s changed unspecified control", provider)
			}
		}
	}
	wire := openAICompatibleRequest{Thinking: "sentinel"}
	applyHybridReasoningControl("openai", &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"enabled": false}}, &wire)
	if wire.Thinking != "sentinel" {
		t.Fatal("changed unrelated provider")
	}
	applyHybridReasoningControl("zai", nil, &wire)
}

func TestKimiExplicitReasoningOnWithToolsDoesNotSilentlyTurnOff(t *testing.T) {
	called := false
	httpc := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		t.Fatal("conflicting request reached provider")
		return nil, nil
	})}
	req := &qtypes.OpenAIChatRequest{Model: "moonshotai/kimi-k2.6", Reasoning: map[string]any{"enabled": true}, Tools: []any{map[string]any{"type": "function"}}}
	err := invokeOpenAICompatibleStreamingWithClientOptions(t.Context(), httpc, "kimi", "https://provider.test/v1", "test-key", req, &qtypes.AnthropicMessagesRequest{}, io.Discard, "kimi-k2.6", openAICompatibleInvocationOptions{})
	if called || err == nil {
		t.Fatalf("called=%v err=%v", called, err)
	}
	upstream, ok := err.(*upstreamHTTPError)
	if !ok || upstream.status != http.StatusBadRequest {
		t.Fatalf("wrong error: %v", err)
	}
}
