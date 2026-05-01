//go:build llm_openrouter

package llm

import (
	"bytes"
	"strings"
	"testing"
)

// TestTranslateOpenAIStreamToAnthropic walks through a representative
// OpenAI streaming response and confirms we emit the three Anthropic SSE
// events the downstream adapter expects: content_block_delta (text),
// message_delta (stop_reason), message_stop.
func TestTranslateOpenAIStreamToAnthropic(t *testing.T) {
	in := strings.Join([]string{
		`data: {"id":"x","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}`,
		``,
		`data: {"id":"x","choices":[{"delta":{"content":"Hello, "},"finish_reason":null}]}`,
		``,
		`data: {"id":"x","choices":[{"delta":{"content":"world."},"finish_reason":null}]}`,
		``,
		`data: {"id":"x","choices":[{"delta":{},"finish_reason":"stop"}]}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")

	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(in), &out); err != nil {
		t.Fatalf("translate: %v", err)
	}

	got := out.String()
	wantSubstrings := []string{
		`event: content_block_delta`,
		`"type":"text_delta"`,
		`"text":"Hello, "`,
		`"text":"world."`,
		`event: message_delta`,
		`"stop_reason":"end_turn"`,
		`event: message_stop`,
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(got, s) {
			t.Errorf("output missing substring %q\n--full output--\n%s", s, got)
		}
	}
}

func TestMapOpenAIFinishReason(t *testing.T) {
	cases := map[string]string{
		"stop":           "end_turn",
		"length":         "max_tokens",
		"tool_calls":     "tool_use",
		"content_filter": "end_turn",
		"weird":          "end_turn",
		"":               "end_turn",
	}
	for in, want := range cases {
		if got := mapOpenAIFinishReason(in); got != want {
			t.Errorf("mapOpenAIFinishReason(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnknownModelRejected(t *testing.T) {
	c := &openRouterClient{apiKey: "test"}
	err := c.InvokeStreaming(t.Context(), "gpt-5-omg", nil, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "unknown model") {
		t.Errorf("expected unknown-model error, got %v", err)
	}
}

func TestParseProvidersEnv(t *testing.T) {
	cases := map[string][]string{
		"":          {"google-vertex"},
		"   ":       {"google-vertex"},
		"anthropic": {"anthropic"},
		"anthropic, google-vertex":                 {"anthropic", "google-vertex"},
		"anthropic , amazon-bedrock,google-vertex": {"anthropic", "amazon-bedrock", "google-vertex"},
		",,,":                                      {"google-vertex"}, // all-empty falls back to default
	}
	for in, want := range cases {
		t.Setenv("QUILL_OPENROUTER_PROVIDERS", in)
		got := parseProvidersEnv()
		if len(got) != len(want) {
			t.Errorf("parseProvidersEnv(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("parseProvidersEnv(%q)[%d] = %q, want %q", in, i, got[i], want[i])
			}
		}
	}
}
