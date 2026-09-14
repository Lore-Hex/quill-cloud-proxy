package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestRegoloStreamingBillableReasoning(t *testing.T) {
	// Native Regolo SSE usage captured on 2026-09-14. Unlike its JSON
	// responses, completion_tokens and total_tokens exclude reasoning.
	for _, tc := range []struct {
		provider, model       string
		completion, reasoning int
		wantOutput            int
	}{
		{"regolo", "qwen3.5-9b", 3, 167, 170},
		{"regolo", "glm5.2", 2, 137, 139},
		{"regolo", "qwen3.5-122b", 3, 140, 143},
		{"regolo", "qwen3.8-27b", 3, 37, 40},
		{"regolo", "gpt-oss-20b", 2, 28, 30},
		{"regolo", "gemma4-31b", 3, 0, 3},
		{"regolo", "long-answer", 100, 10, 110},
		{"openai", "inclusive-reasoning", 139, 137, 139},
		{"kimi", "inclusive-reasoning", 907, 880, 907},
	} {
		t.Run(tc.provider+"/"+tc.model, func(t *testing.T) {
			usageChunk := fmt.Sprintf(`data: {"choices":[],"usage":{"prompt_tokens":16,"completion_tokens":%d,"total_tokens":%d,"completion_tokens_details":{"reasoning_tokens":%d}}}`, tc.completion, 16+tc.completion, tc.reasoning)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = fmt.Fprintln(w, `data: {"choices":[{"delta":{"content":"PONG"},"finish_reason":"stop"}]}`)
				// Repeated cumulative reports must not double-count reasoning.
				_, _ = fmt.Fprintln(w, usageChunk)
				_, _ = fmt.Fprintln(w, usageChunk)
				_, _ = fmt.Fprintln(w, "data: [DONE]")
			}))
			defer server.Close()
			var out bytes.Buffer
			err := invokeOpenAICompatibleStreamingWithClient(
				t.Context(), server.Client(), tc.provider, server.URL, "test-key",
				&qtypes.OpenAIChatRequest{Model: tc.model},
				&qtypes.AnthropicMessagesRequest{MaxTokens: 512, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}},
				&out, tc.model,
			)
			if err != nil {
				t.Fatal(err)
			}
			var finalUsage map[string]int
			for _, line := range strings.Split(out.String(), "\n") {
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				var event struct {
					Type  string         `json:"type"`
					Usage map[string]int `json:"usage"`
				}
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) == nil && event.Type == "message_delta" {
					finalUsage = event.Usage
				}
			}
			if finalUsage["input_tokens"] != 16 || finalUsage["output_tokens"] != tc.wantOutput || finalUsage["reasoning_tokens"] != tc.reasoning {
				t.Fatalf("billable usage = %v; want input=16 output=%d reasoning=%d", finalUsage, tc.wantOutput, tc.reasoning)
			}
		})
	}
}
