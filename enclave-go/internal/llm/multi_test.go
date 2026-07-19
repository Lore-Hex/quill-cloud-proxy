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
		wantWaferZDR  bool
	}{
		{"openai", "openai/gpt-4o-mini", "openai/gpt-4o-mini", "gpt-4o-mini", false},
		{"google-ai-studio", "google/gemini-2.5-flash", "google/gemini-2.5-flash", "gemini-2.5-flash", false},
		{"cerebras", "meta-llama/llama-3.1-8b-instruct", "meta-llama/llama-3.1-8b-instruct", "llama3.1-8b", false},
		{"deepseek", "deepseek/deepseek-v4-flash", "deepseek/deepseek-v4-flash", "deepseek-v4-flash", false},
		{"mistral", "mistralai/mistral-small-2603", "mistralai/mistral-small-2603", "mistral-small-2603", false},
		{"fireworks", "openai/gpt-oss-120b", "accounts/fireworks/models/gpt-oss-120b", "accounts/fireworks/models/gpt-oss-120b", false},
		{"friendli", "z-ai/glm-5.2", "zai-org/GLM-5.2", "zai-org/GLM-5.2", false},
		{"baseten", "z-ai/glm-5.2", "zai-org/GLM-5.2", "zai-org/GLM-5.2", false},
		{"baseten", "nvidia/nemotron-3-ultra-550b-a55b", "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B", "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B", false},
		{"thinkingmachines", "thinkingmachines/inkling", "thinkingmachines/Inkling:peft:262144", "thinkingmachines/Inkling:peft:262144", false},
		{"wafer", "z-ai/glm-5.2", "GLM-5.2", "GLM-5.2", true},
		{"wafer", "moonshotai/kimi-k2.7-code", "Kimi-K2.7-Code", "Kimi-K2.7-Code", false},
		{"wafer", "qwen/qwen3.6-35b-a3b", "Qwen3.6-35B-A3B", "Qwen3.6-35B-A3B", false},
		{"crusoe", "z-ai/glm-5.2", "zai/GLM-5.2", "zai/GLM-5.2", false},
		{"makora", "z-ai/glm-5.2", "zai-org/GLM-5.2-FP8", "zai-org/GLM-5.2-FP8", false},
		{"nebius", "Qwen/Qwen3.5-397B-A17B", "Qwen/Qwen3.5-397B-A17B", "Qwen/Qwen3.5-397B-A17B", false},
		{"minimax", "minimax/minimax-m2.7", "MiniMax-M2.7", "MiniMax-M2.7", false},
		{"inceptron", "moonshotai/kimi-k2.7-code", "moonshotai/Kimi-K2.7-Code", "moonshotai/Kimi-K2.7-Code", false},
		{"morph", "z-ai/glm-5.2", "morph-glm52-744b", "morph-glm52-744b", false},
		{"atlas-cloud", "z-ai/glm-5.2", "zai-org/glm-5.2", "zai-org/glm-5.2", false},
		{"streamlake", "kwaipilot/kat-coder-pro-v2.5", "kat-coder-pro-v2.5", "kat-coder-pro-v2.5", false},
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
				if tt.provider == "wafer" {
					got := r.Header.Get("Wafer-ZDR")
					if tt.wantWaferZDR && got != "required" {
						t.Fatalf("Wafer-ZDR header = %q, want required", got)
					}
					if !tt.wantWaferZDR && got != "" {
						t.Fatalf("Wafer-ZDR header = %q, want omitted", got)
					}
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
				openai:           client,
				googleAIStudio:   client,
				cerebras:         client,
				deepseek:         client,
				mistral:          client,
				fireworks:        client,
				friendli:         client,
				baseten:          client,
				thinkingmachines: client,
				wafer:            client,
				crusoe:           client,
				makora:           client,
				nebius:           client,
				minimax:          client,
				inceptron:        client,
				morph:            client,
				atlasCloud:       client,
				streamLake:       client,
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

func TestGoogleProviderNormalizationKeepsProductsDistinct(t *testing.T) {
	tests := map[string]string{
		"gemini":           "gemini",
		"google":           "gemini",
		"google-ai-studio": "google-ai-studio",
		"ai-studio":        "google-ai-studio",
		"google-vertex":    "google-vertex",
		"google-vertex-ai": "google-vertex",
		"vertex-ai":        "google-vertex",
	}
	for input, want := range tests {
		if got := normalizeDirectProvider(input); got != want {
			t.Errorf("normalizeDirectProvider(%q) = %q, want %q", input, got, want)
		}
	}
	if got := directBaseURL("google-ai-studio"); got != "https://generativelanguage.googleapis.com/v1beta/openai" {
		t.Fatalf("AI Studio base URL = %q", got)
	}
	if got := directBaseURL("google-vertex"); got != "" {
		t.Fatalf("Vertex must not use API-key compatible base URL, got %q", got)
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
		// 4.0 GA models map to their dated snapshot ids (the undated
		// "claude-opus-4"/"claude-sonnet-4" 404 on Anthropic's API).
		"anthropic/claude-opus-4":     "claude-opus-4-20250514",
		"anthropic/claude-opus-4.1":   "claude-opus-4-1",
		"anthropic/claude-opus-4.5":   "claude-opus-4-5",
		"anthropic/claude-opus-4.6":   "claude-opus-4-6",
		"anthropic/claude-opus-4.7":   "claude-opus-4-7",
		"anthropic/claude-sonnet-4":   "claude-sonnet-4-20250514",
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
