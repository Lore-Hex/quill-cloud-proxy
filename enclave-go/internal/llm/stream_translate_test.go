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

func TestTranslateOpenAIStreamRelaysActualServiceTier(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"service_tier":"default","choices":[{"delta":{"content":"PONG"},"finish_reason":"stop"}]}`,
		`data: {"service_tier":"default","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":2,"total_tokens":9}}`,
		`data: [DONE]`,
		``,
	}, "\n")

	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(upstream), &out); err != nil {
		t.Fatalf("translateOpenAIStreamToAnthropic: %v", err)
	}
	if !strings.Contains(out.String(), `"service_tier":"default"`) {
		t.Fatalf("actual service tier not relayed: %s", out.String())
	}
}

// Perplexity Sonar places source provenance beside choices. The provider
// repeats these fields on streamed chunks, so the OpenAI-to-Anthropic
// normalization boundary must retain them for the public response adapter.
func TestTranslateOpenAIStreamRelaysCitationsAndSearchResults(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"The current answer[1]."},"finish_reason":null}],"citations":["https://gov.example/current"],"search_results":[{"title":"Official current page","url":"https://gov.example/current","date":"2026-08-29","snippet":"Current official information."}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"stop"}],"citations":["https://gov.example/current"]}`,
		`data: [DONE]`,
		``,
	}, "\n")

	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(upstream), &out); err != nil {
		t.Fatalf("translateOpenAIStreamToAnthropic: %v", err)
	}
	body := out.String()
	for _, want := range []string{
		`"trustedrouter_citations":["https://gov.example/current"]`,
		`"title":"Official current page"`,
		`"snippet":"Current official information."`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("provider provenance lost; missing %s in translated stream: %s", want, body)
		}
	}
}

func TestTranslateOpenAIStreamInfersUnclassifiedReasoningFromTotalTokens(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"PONG"},"finish_reason":"stop"}]}`,
		`data: {"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":2,"total_tokens":93}}`,
		`data: [DONE]`,
		``,
	}, "\n")

	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(upstream), &out); err != nil {
		t.Fatalf("translateOpenAIStreamToAnthropic: %v", err)
	}

	body := out.String()
	for _, want := range []string{
		`"input_tokens":7`,
		`"output_tokens":86`,
		`"reasoning_tokens":84`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in translated usage: %s", want, body)
		}
	}
}

// TestTranslateOpenAIStreamRelaysCachedTokens: OpenAI-style automatic
// prompt caching reports prompt_tokens_details.cached_tokens; it must
// relay as cache_read_input_tokens on the synthetic message_delta.
func TestTranslateOpenAIStreamRelaysCachedTokens(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"Hi"},"finish_reason":"stop"}]}`,
		`data: {"choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":5,"total_tokens":1005,"prompt_tokens_details":{"cached_tokens":900}}}`,
		`data: [DONE]`,
		``,
	}, "\n")
	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(upstream), &out); err != nil {
		t.Fatalf("translateOpenAIStreamToAnthropic: %v", err)
	}
	if !strings.Contains(out.String(), `"cache_read_input_tokens":900`) {
		t.Fatalf("cached_tokens not relayed: %s", out.String())
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

func TestTranslateOpenAIStreamMapsContentFilterToInternalStopReason(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{},"finish_reason":"content_filter"}]}`,
		`data: [DONE]`,
		``,
	}, "\n")
	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(upstream), &out); err != nil {
		t.Fatalf("translateOpenAIStreamToAnthropic: %v", err)
	}
	if !strings.Contains(out.String(), `"stop_reason":"`+qtypes.SyntheticStopReasonContentFilter+`"`) {
		t.Fatalf("content_filter marker not mapped: %s", out.String())
	}
}

func TestTranslateOpenAIStreamPreservesReasoningContentAsThinking(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"reasoning_content":"think first"},"finish_reason":null}]}`,
		`data: {"choices":[{"delta":{"content":"answer"},"finish_reason":"stop"}]}`,
		`data: [DONE]`,
		``,
	}, "\n")
	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(upstream), &out); err != nil {
		t.Fatalf("translateOpenAIStreamToAnthropic: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, `"type":"thinking"`) || !strings.Contains(body, `"thinking":"think first"`) || !strings.Contains(body, `"type":"thinking_delta"`) {
		t.Fatalf("reasoning_content was not preserved as thinking: %s", body)
	}
	if !strings.Contains(body, `"type":"text_delta"`) || !strings.Contains(body, `"text":"answer"`) {
		t.Fatalf("visible content lost: %s", body)
	}
	if strings.Contains(body, `"type":"text_delta","text":"think first"`) {
		t.Fatalf("reasoning_content leaked into visible text: %s", body)
	}
}

func TestTranslateMuseStreamKeepsVisibleTextAndDropsEncryptedReasoning(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"reasoning_details":[{"type":"reasoning.encrypted","data":"TOP_SECRET_BLOB"}]},"finish_reason":null}]}`,
		`data: {"choices":[{"delta":{"content":"PONG"},"finish_reason":"stop"}]}`,
		`data: {"choices":[],"usage":{"prompt_tokens":169,"completion_tokens":110,"total_tokens":279,"prompt_tokens_details":{"cached_tokens":165},"completion_tokens_details":{"reasoning_tokens":98}}}`,
		`data: [DONE]`,
		``,
	}, "\n")

	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(upstream), &out); err != nil {
		t.Fatalf("translateOpenAIStreamToAnthropic: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, `"text":"PONG"`) {
		t.Fatalf("Muse visible content lost: %s", body)
	}
	if strings.Contains(body, "TOP_SECRET_BLOB") || strings.Contains(body, "reasoning.encrypted") {
		t.Fatalf("encrypted reasoning details leaked downstream: %s", body)
	}
	for _, want := range []string{
		`"input_tokens":169`,
		`"output_tokens":110`,
		`"cache_read_input_tokens":165`,
		`"reasoning_tokens":98`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in translated usage: %s", want, body)
		}
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

func TestOpenAIStreamUsageCachedTokensPrecedence(t *testing.T) {
	cases := []struct {
		name  string
		usage openAIStreamUsage
		want  int
	}{
		{"openai standard nested", openAIStreamUsage{PromptTokensDetails: &openAIPromptTokenDetails{CachedTokens: 100}}, 100},
		{"moonshot kimi top-level cached_tokens", openAIStreamUsage{CachedTokensTop: 200}, 200},
		{"deepseek prompt_cache_hit_tokens", openAIStreamUsage{PromptCacheHitTokens: 300}, 300},
		{"standard wins over fallbacks", openAIStreamUsage{PromptTokensDetails: &openAIPromptTokenDetails{CachedTokens: 1}, CachedTokensTop: 2, PromptCacheHitTokens: 3}, 1},
		{"none reported", openAIStreamUsage{PromptTokens: 50}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.usage.cachedTokens(); got != tc.want {
				t.Fatalf("cachedTokens() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestOpenAIStreamUsageIncludesSakanaOrchestrationTokens(t *testing.T) {
	usage := openAIStreamUsage{
		PromptTokens:     5,
		CompletionTokens: 22,
		TotalTokens:      27,
		PromptTokensDetails: &openAIPromptTokenDetails{
			CachedTokens:                   2,
			OrchestrationInputTokens:       1260,
			OrchestrationInputCachedTokens: 1200,
		},
		CompletionTokensDetails: &openAIStreamUsageDetails{
			ReasoningTokens:           3,
			OrchestrationOutputTokens: 40,
		},
	}

	if got := usage.inputTokens(); got != 1265 {
		t.Fatalf("inputTokens() = %d, want 1265", got)
	}
	if got := usage.cachedTokens(); got != 1202 {
		t.Fatalf("cachedTokens() = %d, want 1202", got)
	}
	if got := usage.outputTokens(); got != 62 {
		t.Fatalf("outputTokens() = %d, want 62", got)
	}
}

func TestTranslateOpenAIStreamSurfacesSakanaOrchestrationUsage(t *testing.T) {
	var out bytes.Buffer
	in := "data: " + `{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":22,"total_tokens":27,"prompt_tokens_details":{"cached_tokens":2,"orchestration_input_tokens":1260,"orchestration_input_cached_tokens":1200},"completion_tokens_details":{"reasoning_tokens":3,"orchestration_output_tokens":40}}}` + "\n\ndata: [DONE]\n\n"
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(in), &out); err != nil {
		t.Fatalf("translate: %v", err)
	}
	for _, want := range []string{
		`"input_tokens":1265`,
		`"output_tokens":62`,
		`"cache_read_input_tokens":1202`,
		`"price_tier_input_tokens":5`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s in output: %s", want, out.String())
		}
	}
}

// DeepSeek (prompt_cache_hit_tokens) and Moonshot/Kimi (top-level cached_tokens)
// report cache hits in non-OpenAI-standard fields; both must surface as
// cache_read_input_tokens in the translated Anthropic stream.
func TestTranslateOpenAIStreamSurfacesNonStandardCacheFields(t *testing.T) {
	cases := []struct{ name, chunk, wantSub string }{
		{"deepseek", `{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":80,"completion_tokens":5,"prompt_cache_hit_tokens":64}}`, `"cache_read_input_tokens":64`},
		{"kimi", `{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":80,"completion_tokens":5,"cached_tokens":70}}`, `"cache_read_input_tokens":70`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			in := "data: " + tc.chunk + "\n\ndata: [DONE]\n\n"
			if err := translateOpenAIStreamToAnthropic(strings.NewReader(in), &out); err != nil {
				t.Fatalf("translate: %v", err)
			}
			if !strings.Contains(out.String(), tc.wantSub) {
				t.Fatalf("missing %s in output: %s", tc.wantSub, out.String())
			}
		})
	}
}
