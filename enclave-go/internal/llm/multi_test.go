//go:build llm_multi

package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestMultiClientDispatchesPrepaidOpenAICompatibleProviders(t *testing.T) {
	tests := []struct {
		provider      string
		publicModel   string
		upstreamModel string
		wantModel     string
	}{
		{"openai", "openai/gpt-4o-mini", "openai/gpt-4o-mini", "gpt-4o-mini"},
		{"cerebras", "meta-llama/llama-3.1-8b-instruct", "meta-llama/llama-3.1-8b-instruct", "llama3.1-8b"},
		{"deepseek", "deepseek/deepseek-v4-flash", "deepseek/deepseek-v4-flash", "deepseek-v4-flash"},
		{"mistral", "mistralai/mistral-small-2603", "mistralai/mistral-small-2603", "mistral-small-2603"},
		{"nebius", "Qwen/Qwen3.5-397B-A17B", "Qwen/Qwen3.5-397B-A17B", "Qwen/Qwen3.5-397B-A17B"},
		{"minimax", "minimax/minimax-m2.7", "MiniMax-M2.7", "MiniMax-M2.7"},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			var captured map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/chat/completions" {
					t.Fatalf("path = %s, want /chat/completions", r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer operator-key" {
					t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
				}
				if r.Header.Get("User-Agent") != "TrustedRouter/1.0" {
					t.Fatalf("user-agent = %q", r.Header.Get("User-Agent"))
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("read body: %v", err)
				}
				if err := json.Unmarshal(body, &captured); err != nil {
					t.Fatalf("decode request: %v", err)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(strings.Join([]string{
					`data: {"id":"x","choices":[{"delta":{"content":"ok"},"finish_reason":null}]}`,
					``,
					`data: {"id":"x","choices":[{"delta":{},"finish_reason":"stop"}]}`,
					``,
					`data: [DONE]`,
					``,
				}, "\n")))
			}))
			defer server.Close()

			client := &openAICompatibleClient{
				provider: tt.provider,
				baseURL:  server.URL,
				apiKey:   "operator-key",
				httpc:    server.Client(),
			}
			multi := &multiClient{
				openai:   client,
				cerebras: client,
				deepseek: client,
				mistral:  client,
				nebius:   client,
				minimax:  client,
			}
			req := &qtypes.OpenAIChatRequest{Model: tt.publicModel}
			body := &qtypes.AnthropicMessagesRequest{
				Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "hello"}},
				MaxTokens: 8,
			}
			var out bytes.Buffer

			err := multi.InvokeStreaming(
				t.Context(),
				req,
				body,
				&out,
				InvokeOptions{
					Model:         tt.publicModel,
					UpstreamModel: tt.upstreamModel,
					Provider:      tt.provider,
					UsageType:     "Credits",
				},
			)
			if err != nil {
				t.Fatalf("InvokeStreaming: %v", err)
			}
			if captured["model"] != tt.wantModel {
				t.Fatalf("upstream model = %#v, want %q; payload=%#v", captured["model"], tt.wantModel, captured)
			}
			if _, ok := captured["response_format"]; ok {
				t.Fatalf("nil response_format leaked into upstream payload: %#v", captured)
			}
			if !strings.Contains(out.String(), "content_block_delta") {
				t.Fatalf("stream was not translated to Anthropic SSE: %s", out.String())
			}
		})
	}
}

func TestDirectModelIDStripsOpenRouterVariants(t *testing.T) {
	tests := map[string]string{
		"google/gemma-3-27b-it:free":    "gemma-3-27b-it",
		"z-ai/glm-4.5-air:free":         "glm-4.5-air",
		"openai/gpt-4o-mini:nitro":      "gpt-4o-mini",
		"mistralai/mistral-small:floor": "mistral-small",
	}

	for public, want := range tests {
		got := directModelID("gemini", public, public)
		if got != want {
			t.Fatalf("directModelID(%q) = %q, want %q", public, got, want)
		}
	}
}

func TestAnthropicCatalogModelsNormalizeToProviderIDs(t *testing.T) {
	tests := map[string]string{
		"anthropic/claude-opus-4":     "claude-opus-4",
		"anthropic/claude-opus-4.1":   "claude-opus-4-1",
		"anthropic/claude-opus-4.5":   "claude-opus-4-5",
		"anthropic/claude-opus-4.6":   "claude-opus-4-6",
		"anthropic/claude-opus-4.7":   "claude-opus-4-7",
		"anthropic/claude-opus-4.8":   "claude-opus-4-8",
		"anthropic/claude-sonnet-4":   "claude-sonnet-4",
		"anthropic/claude-sonnet-4.5": "claude-sonnet-4-5",
		"anthropic/claude-sonnet-4.6": "claude-sonnet-4-6",
		"anthropic/claude-haiku-4.5":  "claude-haiku-4-5",
		"claude-3-5-sonnet-20241022":  "claude-3-5-sonnet-20241022",
	}

	for public, want := range tests {
		if got := mapModelID(public); got != want {
			t.Fatalf("mapModelID(%q) = %q, want %q", public, got, want)
		}
	}
}

func TestAnthropicSamplingParamsOmitDeprecatedOpus48Fields(t *testing.T) {
	temperature := 0.2
	topP := 0.9

	gotTemperature, gotTopP := anthropicSamplingParams("claude-opus-4-8", &temperature, &topP)
	if gotTemperature != nil || gotTopP != nil {
		t.Fatalf("claude-opus-4-8 sampling params = (%v, %v), want nil, nil", gotTemperature, gotTopP)
	}

	gotTemperature, gotTopP = anthropicSamplingParams("claude-opus-4-7", &temperature, &topP)
	if gotTemperature == nil || *gotTemperature != temperature {
		t.Fatalf("claude-opus-4-7 temperature = %v, want %v", gotTemperature, temperature)
	}
	if gotTopP == nil || *gotTopP != topP {
		t.Fatalf("claude-opus-4-7 top_p = %v, want %v", gotTopP, topP)
	}
}
