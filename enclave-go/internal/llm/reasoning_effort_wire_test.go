package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestChatEffortReachesAnthropicNativeWire(t *testing.T) {
	for _, model := range []string{"claude-opus-4-8", "claude-sonnet-4-6", "claude-sonnet-5"} {
		for _, effort := range []string{"low", "medium", "high", "xhigh", "max"} {
			if model == "claude-sonnet-4-6" && effort == "xhigh" {
				continue
			}
			t.Run(model+"/"+effort, func(t *testing.T) {
				req := &qtypes.OpenAIChatRequest{Model: model, ReasoningEffort: effort,
					Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "Reply OK"}}}
				body, err := adapter.ToAnthropic(req, model)
				if err != nil {
					t.Fatal(err)
				}
				httpc := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					var wire map[string]any
					if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
						t.Fatal(err)
					}
					config, _ := wire["output_config"].(map[string]any)
					if config["effort"] != effort {
						t.Fatalf("output_config = %#v, want effort %s", config, effort)
					}
					thinking, _ := wire["thinking"].(map[string]any)
					if thinking["type"] != "adaptive" || thinking["budget_tokens"] != nil {
						t.Fatalf("thinking = %#v", thinking)
					}
					if wire["max_tokens"] != float64(adapter.DefaultMaxTokens) {
						t.Fatalf("effort inflated max_tokens: %#v", wire["max_tokens"])
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")), Header: make(http.Header)}, nil
				})}
				if err := invokeAnthropicBYOKStreamingWithClient(t.Context(), httpc, req, body, io.Discard, "test-key", model); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestAnthropicReasoningPreservesNativeAndFallbackBodies(t *testing.T) {
	original := &qtypes.AnthropicMessagesRequest{MaxTokens: 4096, AnthropicMaxTokens: 12288,
		Thinking:     map[string]any{"type": "enabled", "budget_tokens": 8192},
		OutputConfig: map[string]any{"format": map[string]any{"type": "json_schema"}}}
	req := &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"effort": "max"}}
	got := anthropicChatReasoningBody("claude-opus-4-8", req, original)
	if got.OutputConfig.(map[string]any)["effort"] != "max" || got.OutputConfig.(map[string]any)["format"] == nil {
		t.Fatalf("output_config=%#v", got.OutputConfig)
	}
	if original.AnthropicMaxTokens != 12288 || original.OutputConfig.(map[string]any)["effort"] != nil || original.Thinking.(map[string]any)["type"] != "enabled" {
		t.Fatal("mutated shared fallback body")
	}
	original.NativeContent = true
	if anthropicChatReasoningBody("claude-opus-4-8", req, original) != original {
		t.Fatal("reinterpreted native Messages body")
	}
	original.NativeContent = false
	if anthropicChatReasoningBody("claude-haiku-4-5", req, original) != original {
		t.Fatal("changed budget-only model")
	}
	req.Reasoning = map[string]any{"effort": "high", "max_tokens": 8192}
	got = anthropicChatReasoningBody("claude-sonnet-4-6", req, original)
	if got.Thinking.(map[string]any)["budget_tokens"] != 8192 || got.AnthropicMaxTokens != 12288 {
		t.Fatal("discarded explicit caller budget")
	}
	req.Reasoning = map[string]any{"enabled": false}
	req.ReasoningEffort = "high"
	got = anthropicChatReasoningBody("claude-sonnet-4-6", req, original)
	if got.Thinking.(map[string]any)["type"] != "disabled" {
		t.Fatal("explicit Off ignored")
	}
}

func TestChatEffortPreservesNativeThinkingBudget(t *testing.T) {
	req := &qtypes.OpenAIChatRequest{ReasoningEffort: "high"}
	body := &qtypes.AnthropicMessagesRequest{NativeContent: true, Thinking: map[string]any{"type": "enabled", "budget_tokens": 2048}}
	wire := buildOpenAICompatibleRequest("kimi", "kimi-k3", req, body, nil)
	if wire.Thinking.(map[string]any)["budget_tokens"] != 2048 {
		t.Fatal("erased native thinking budget")
	}
}

func TestOpenAIStyleEffortNeverLeaksAnthropicBudget(t *testing.T) {
	for provider, model := range map[string]string{"openai": "gpt-5.5", "kimi": "kimi-k3", "gemini": "gemini-3.8-flash", "deepseek": "deepseek-flash", "zai": "glm-5.3", "mistral": "mistral-medium-3-5", "alibaba": "qwen3.8-max"} {
		for _, nested := range []bool{false, true} {
			req := &qtypes.OpenAIChatRequest{Model: model, ReasoningEffort: "high", Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "Reply OK"}}}
			if nested {
				req.ReasoningEffort = ""
				req.Reasoning = map[string]any{"effort": "high"}
			}
			body, err := adapter.ToAnthropic(req, model)
			if err != nil {
				t.Fatal(err)
			}
			wire := buildOpenAICompatibleRequest(provider, model, req, body, nil)
			if wire.ReasoningEffort != "high" {
				t.Errorf("%s nested=%t effort=%q", provider, nested, wire.ReasoningEffort)
			}
			if wire.Thinking != nil {
				t.Errorf("%s nested=%t leaked thinking=%#v", provider, nested, wire.Thinking)
			}
			if wire.Reasoning != nil {
				t.Errorf("%s nested=%t leaked reasoning=%#v", provider, nested, wire.Reasoning)
			}
		}
	}
}
