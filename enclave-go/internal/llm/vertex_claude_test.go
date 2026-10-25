//go:build llm_multi

package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestPublicVertexClaudeUsesNativePublisherAndGlobalOAuth(t *testing.T) {
	for _, native := range []string{"claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-haiku-4-5@20251001"} {
		t.Run(native, func(t *testing.T) {
			calls := 0
			auth := &gcpClient{
				projectID: "test-project", region: "global",
				token: "vertex-token", tokenExp: time.Now().Add(time.Hour),
				httpc: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.URL.Host != "aiplatform.googleapis.com" || r.URL.Path != "/v1/projects/test-project/locations/global/publishers/anthropic/models/"+native+":streamRawPredict" {
						t.Fatalf("wrong publisher/location: %s", r.URL)
					}
					if r.Header.Get("Authorization") != "Bearer vertex-token" || r.Header.Get("x-api-key") != "" {
						t.Fatal("must use Vertex OAuth, never Anthropic-direct credentials")
					}
					var wire map[string]any
					if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
						t.Fatal(err)
					}
					if wire["anthropic_version"] != vertexAnthropicVersion || wire["stream"] != true || wire["model"] != nil || wire["max_tokens"] != float64(128) {
						t.Fatalf("wrong native request: %#v", wire)
					}
					if wire["tools"] == nil || wire["system"] != "system prompt" {
						t.Fatalf("lost tool/system fields: %#v", wire)
					}
					sse := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"test\",\"role\":\"assistant\",\"content\":[],\"model\":\"" + native + "\",\"usage\":{\"input_tokens\":10,\"output_tokens\":0,\"cache_read_input_tokens\":5}}}\n\n" +
						"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"PONG\"}}\n\n" +
						"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n" +
						"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(sse))}, nil
				})},
			}
			// Other clients deliberately nil: this route must never silently
			// fall back to Anthropic-direct or the legacy regional client.
			client := &multiClient{googleVertex: &vertexGeminiClient{auth: auth}}
			req := &qtypes.OpenAIChatRequest{Model: "anthropic/claude-opus-5.5"}
			body := &qtypes.AnthropicMessagesRequest{
				MaxTokens: 128, System: "system prompt",
				Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Reply PONG"}},
				Tools:    []qtypes.AnthropicTool{{Name: "lookup", InputSchema: map[string]any{"type": "object"}}},
			}
			var out bytes.Buffer
			err := client.InvokeStreaming(t.Context(), req, body, &out, InvokeOptions{Provider: "google-vertex", UpstreamModel: native})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || !strings.Contains(out.String(), "PONG") || !strings.Contains(out.String(), "cache_read_input_tokens") || !strings.Contains(out.String(), "message_stop") {
				t.Fatalf("lost response or usage: calls=%d output=%s", calls, &out)
			}
		})
	}
}

func TestPublicVertexClaudeRejectsUpstreamFailuresWithoutFallback(t *testing.T) {
	for _, status := range []int{403, 404, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			auth := &gcpClient{
				projectID: "test-project", region: "global",
				token: "vertex-token", tokenExp: time.Now().Add(time.Hour),
				httpc: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":{"message":"unavailable"}}`))}, nil
				})},
			}
			client := &multiClient{googleVertex: &vertexGeminiClient{auth: auth}}
			req := &qtypes.OpenAIChatRequest{Model: "anthropic/claude-sonnet-5.5"}
			body := &qtypes.AnthropicMessagesRequest{MaxTokens: 32, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}}}
			var out bytes.Buffer
			err := client.InvokeStreaming(t.Context(), req, body, &out, InvokeOptions{Provider: "google-vertex", UpstreamModel: "claude-sonnet-5-5"})
			if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) || calls != 1 || out.Len() != 0 {
				t.Fatalf("failure must propagate without response bytes/fallback: err=%v calls=%d output=%q", err, calls, out.String())
			}
		})
	}
}

func TestPublicVertexClaudeCacheWriteBillingGuard(t *testing.T) {
	for _, where := range []string{"system", "message", "tool_result"} {
		for _, ttl := range []string{"5m", "1h"} {
			t.Run(where+"/"+ttl, func(t *testing.T) {
				blocks := []any{map[string]any{"type": "text", "text": "prefix", "cache_control": map[string]any{"type": "ephemeral", "ttl": ttl}}}
				body := &qtypes.AnthropicMessagesRequest{}
				switch where {
				case "system":
					body.SystemRaw = blocks
				case "message":
					body.Messages = []qtypes.AnthropicMessage{{Role: "user", Content: blocks}}
				case "tool_result":
					body.Messages = []qtypes.AnthropicMessage{{Role: "user", Content: []any{map[string]any{"type": "tool_result", "tool_use_id": "tool-1", "content": blocks}}}}
				}
				err := validateVertexClaudeCacheTTL(body)
				if (err != nil) != (ttl == "1h") {
					t.Fatalf("ttl=%s error=%v", ttl, err)
				}
				if ttl == "1h" {
					// A nil transport proves rejection occurs before any upstream I/O.
					client := &multiClient{}
					err = client.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: "anthropic/claude-sonnet-5.5"}, body, io.Discard, InvokeOptions{Provider: "google-vertex", UpstreamModel: "claude-sonnet-5-5"})
					if err == nil || !strings.Contains(err.Error(), "400") {
						t.Fatalf("expected explicit 400 before dispatch: %v", err)
					}
				}
			})
		}
	}
	var body qtypes.AnthropicMessagesRequest
	if err := json.Unmarshal([]byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tool-1","name":"test","input":{"cache_control":{"ttl":"1h"}}}]}]}`), &body); err != nil {
		t.Fatal(err)
	}
	if err := validateVertexClaudeCacheTTL(&body); err != nil {
		t.Fatalf("tool input is not a cache directive: %v", err)
	}
}
