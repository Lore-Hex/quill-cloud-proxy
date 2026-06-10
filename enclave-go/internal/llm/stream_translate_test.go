package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// TestTranslateOpenAIStreamRelaysUsage locks in the usage relay: the
// final stream_options.include_usage chunk (choices: []) from an OpenAI-
// compatible upstream must land on the synthetic message_delta so the
// adapter can bill REAL token counts instead of chars/4 estimates. The
// pre-fix behavior silently skipped usage-only chunks (len(choices)==0)
// — exactly why reasoning models' hidden tokens were never billed.
func TestTranslateOpenAIStreamRelaysUsage(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"Hello"},"finish_reason":null}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"stop"}]}`,
		`data: {"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":907,"total_tokens":919,"completion_tokens_details":{"reasoning_tokens":880}}}`,
		`data: [DONE]`,
		``,
	}, "\n")

	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(upstream), &out); err != nil {
		t.Fatalf("translateOpenAIStreamToAnthropic: %v", err)
	}

	body := out.String()
	if !strings.Contains(body, `"text":"Hello"`) {
		t.Fatalf("content delta lost: %s", body)
	}
	deltaLine := ""
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"message_delta"`) {
			deltaLine = strings.TrimPrefix(line, "data: ")
		}
	}
	if deltaLine == "" {
		t.Fatalf("no message_delta in output: %s", body)
	}
	var delta struct {
		Usage map[string]int `json:"usage"`
	}
	if err := json.Unmarshal([]byte(deltaLine), &delta); err != nil {
		t.Fatalf("unmarshal message_delta %q: %v", deltaLine, err)
	}
	if delta.Usage["input_tokens"] != 12 || delta.Usage["output_tokens"] != 907 || delta.Usage["reasoning_tokens"] != 880 {
		t.Fatalf("relayed usage = %#v, want 12/907/880", delta.Usage)
	}
}

// TestTranslateOpenAIStreamNoUsageOmitsUsage: upstreams that never report
// usage produce a bare message_delta — the adapter then falls back to
// estimates, same as before this feature.
func TestTranslateOpenAIStreamNoUsageOmitsUsage(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"Hi"},"finish_reason":"stop"}]}`,
		`data: [DONE]`,
		``,
	}, "\n")
	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(upstream), &out); err != nil {
		t.Fatalf("translateOpenAIStreamToAnthropic: %v", err)
	}
	if strings.Contains(out.String(), `"usage"`) {
		t.Fatalf("usage present without upstream usage: %s", out.String())
	}
}

// TestOpenAICompatibleRequestBody locks in the upstream request shape:
//  1. stream_options.include_usage is ALWAYS requested (feeds settlement
//     + the client-facing include_usage chunk);
//  2. max_tokens is OMITTED when the client never set one — forwarding
//     the adapter's required-for-Anthropic 4096 default truncated
//     reasoning models mid-think while the same prompt sent direct ran
//     to the provider's model-max default (the gateway-vs-direct
//     accounting discrepancy, 2026-06);
//  3. a client-set cap is still forwarded verbatim.
func TestOpenAICompatibleRequestBody(t *testing.T) {
	type captured struct {
		MaxTokens           *int `json:"max_tokens"`
		MaxCompletionTokens *int `json:"max_completion_tokens"`
		StreamOptions       *struct {
			IncludeUsage bool `json:"include_usage"`
		} `json:"stream_options"`
	}

	run := func(t *testing.T, body *qtypes.AnthropicMessagesRequest) captured {
		t.Helper()
		var got captured
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("decode upstream body: %v", err)
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
		}))
		defer server.Close()

		req := &qtypes.OpenAIChatRequest{Model: "xiaomi/mimo-v2.5-pro"}
		var out bytes.Buffer
		err := invokeOpenAICompatibleStreamingWithClient(
			context.Background(),
			server.Client(),
			"xiaomi",
			server.URL,
			"test-key",
			req,
			body,
			&out,
			"",
		)
		if err != nil {
			t.Fatalf("invokeOpenAICompatibleStreamingWithClient: %v", err)
		}
		return got
	}

	t.Run("default max_tokens omitted, stream_options sent", func(t *testing.T) {
		got := run(t, &qtypes.AnthropicMessagesRequest{
			Messages:          []qtypes.AnthropicMessage{{Role: "user", Content: "hi"}},
			MaxTokens:         4096, // adapter default — required by Anthropic wire, NOT client intent
			MaxTokensExplicit: false,
		})
		if got.MaxTokens != nil || got.MaxCompletionTokens != nil {
			t.Fatalf("max_tokens forwarded despite client omitting it: %#v", got)
		}
		if got.StreamOptions == nil || !got.StreamOptions.IncludeUsage {
			t.Fatalf("stream_options.include_usage not requested: %#v", got.StreamOptions)
		}
	})

	t.Run("explicit max_tokens forwarded", func(t *testing.T) {
		got := run(t, &qtypes.AnthropicMessagesRequest{
			Messages:          []qtypes.AnthropicMessage{{Role: "user", Content: "hi"}},
			MaxTokens:         123,
			MaxTokensExplicit: true,
		})
		if got.MaxTokens == nil || *got.MaxTokens != 123 {
			t.Fatalf("explicit max_tokens not forwarded: %#v", got)
		}
	})
}
