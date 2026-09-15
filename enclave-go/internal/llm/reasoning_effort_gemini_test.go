//go:build llm_multi

package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestGeminiEveryEffortHasDistinctNativeMapping(t *testing.T) {
	for effort, budget := range map[string]int{"none": 0, "minimal": 1024, "low": 1024, "medium": 8192, "high": 24576} {
		for _, model := range []string{"gemini-2.5-flash", "gemini-2.5-pro"} {
			if model == "gemini-2.5-pro" && effort == "none" {
				continue
			}
			got := vertexGeminiThinkingConfig(model, &qtypes.OpenAIChatRequest{ReasoningEffort: effort})
			if got["thinkingBudget"] != budget {
				t.Errorf("%s/%s = %#v, want budget %d", model, effort, got, budget)
			}
		}
	}
	for _, model := range []string{"gemini-3-flash-preview", "gemini-3.1-pro-preview", "gemini-3.5-flash", "gemini-3.6-flash", "gemini-3.7-flash", "gemini-3.8-flash"} {
		for _, effort := range []string{"low", "medium", "high"} {
			got := vertexGeminiThinkingConfig(model, &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"effort": effort}})
			if got["thinkingLevel"] != effort {
				t.Errorf("%s/%s = %#v", model, effort, got)
			}
		}
	}
}

func TestReasoningReachesPrepaidNativeTransports(t *testing.T) {
	for _, provider := range []string{"anthropic", "vertex", "google-vertex"} {
		t.Run(provider, func(t *testing.T) {
			model := "claude-sonnet-4-6"
			if provider == "google-vertex" {
				model = "gemini-3.1-pro-preview"
			}
			req := &qtypes.OpenAIChatRequest{Model: model, ReasoningEffort: "medium", Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "Reply OK"}}}
			body, err := adapter.ToAnthropic(req, model)
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
				if provider == "google-vertex" {
					config, _ := wire["generationConfig"].(map[string]any)
					thinking, _ := config["thinkingConfig"].(map[string]any)
					if thinking["thinkingLevel"] != "medium" {
						t.Fatalf("thinking = %#v", thinking)
					}
				} else {
					config, _ := wire["output_config"].(map[string]any)
					if config["effort"] != "medium" {
						t.Fatalf("output_config = %#v", config)
					}
				}
				payload := "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
				if provider == "google-vertex" {
					payload = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"OK\"}]},\"finishReason\":\"STOP\"}]}\n\n"
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: make(http.Header)}, nil
			})}
			auth := &gcpClient{projectID: "test", region: "global", httpc: httpc, token: "test-token", tokenExp: time.Now().Add(time.Hour)}
			var client Client
			switch provider {
			case "anthropic":
				client = &anthropicClient{provider: provider, url: anthropicURL, apiKey: "test-key", httpc: httpc}
			case "vertex":
				client = auth
			case "google-vertex":
				client = &vertexGeminiClient{auth: auth}
			}
			if err := client.InvokeStreaming(t.Context(), req, body, io.Discard, InvokeOptions{UpstreamModel: model}); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("calls = %d, want 1", calls)
			}
		})
	}
}
