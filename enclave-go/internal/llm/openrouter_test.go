//go:build llm_openrouter

package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type openRouterRoundTripFunc func(*http.Request) (*http.Response, error)

func (f openRouterRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

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
		"content_filter": qtypes.SyntheticStopReasonContentFilter,
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
	err := c.InvokeStreaming(
		t.Context(),
		&qtypes.OpenAIChatRequest{Model: "gpt-5-omg"},
		&qtypes.AnthropicMessagesRequest{},
		&bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown model") {
		t.Errorf("expected unknown-model error, got %v", err)
	}
}

func TestOpenRouterModelsArrayFallbackAndProviderRouting(t *testing.T) {
	var requests []map[string]any
	c := &openRouterClient{
		apiKey: "test",
		httpc: &http.Client{Transport: openRouterRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				return nil, err
			}
			requests = append(requests, payload)
			if len(requests) == 1 {
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"busy"}}`)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader(strings.Join([]string{
					`data: {"id":"x","choices":[{"delta":{"content":"ok"},"finish_reason":null}]}`,
					``,
					`data: {"id":"x","choices":[{"delta":{},"finish_reason":"stop"}]}`,
					``,
					`data: [DONE]`,
					``,
				}, "\n"))),
			}, nil
		})},
		baseURL:   "https://openrouter.test",
		providers: []string{"google-vertex", "anthropic"},
	}
	allowFallbacks := true
	req := &qtypes.OpenAIChatRequest{
		Model:  "openai/gpt-4o-mini",
		Models: []string{"anthropic/claude-3-5-sonnet"},
		Provider: &qtypes.ProviderRouting{
			Order:          []string{"Anthropic", "Google Vertex"},
			AllowFallbacks: &allowFallbacks,
			DataCollection: "allow",
			Ignore:         []string{"amazon_bedrock"},
			Sort:           "throughput",
		},
	}
	body := &qtypes.AnthropicMessagesRequest{
		Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "hello"}},
		MaxTokens: 8,
	}
	var out bytes.Buffer

	if err := c.InvokeStreaming(t.Context(), req, body, &out); err != nil {
		t.Fatalf("InvokeStreaming: %v", err)
	}

	if len(requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(requests))
	}
	if requests[0]["model"] != "openai/gpt-4o-mini" {
		t.Fatalf("first model = %v", requests[0]["model"])
	}
	if requests[1]["model"] != "anthropic/claude-3.5-sonnet" {
		t.Fatalf("second model = %v", requests[1]["model"])
	}
	provider, ok := requests[1]["provider"].(map[string]any)
	if !ok {
		t.Fatalf("provider routing missing: %#v", requests[1])
	}
	if provider["data_collection"] != "deny" {
		t.Fatalf("data_collection = %v, want deny", provider["data_collection"])
	}
	order, _ := provider["order"].([]any)
	if len(order) != 2 || order[0] != "anthropic" || order[1] != "google-vertex" {
		t.Fatalf("order = %#v", provider["order"])
	}
	ignore, _ := provider["ignore"].([]any)
	if len(ignore) != 1 || ignore[0] != "amazon-bedrock" {
		t.Fatalf("ignore = %#v", provider["ignore"])
	}
	if !strings.Contains(out.String(), `"text":"ok"`) {
		t.Fatalf("missing translated output: %s", out.String())
	}
}

func TestOpenRouterRequestCarriesSeedAndPenalties(t *testing.T) {
	var payload map[string]any
	c := &openRouterClient{
		apiKey:  "test",
		baseURL: "https://openrouter.test",
		httpc: &http.Client{Transport: openRouterRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader(strings.Join([]string{
					`data: {"id":"x","choices":[{"delta":{"content":"ok"},"finish_reason":null}]}`,
					``,
					`data: {"id":"x","choices":[{"delta":{},"finish_reason":"stop"}]}`,
					``,
					`data: [DONE]`,
					``,
				}, "\n"))),
			}, nil
		})},
	}
	seed := 123
	frequencyPenalty := 0.25
	presencePenalty := -0.5
	req := &qtypes.OpenAIChatRequest{
		Model:            "openai/gpt-4o-mini",
		Seed:             &seed,
		FrequencyPenalty: &frequencyPenalty,
		PresencePenalty:  &presencePenalty,
	}
	body := &qtypes.AnthropicMessagesRequest{
		Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "hello"}},
		MaxTokens: 8,
	}
	var out bytes.Buffer

	if err := c.InvokeStreaming(t.Context(), req, body, &out); err != nil {
		t.Fatalf("InvokeStreaming: %v", err)
	}

	if payload["seed"] != float64(seed) {
		t.Fatalf("seed = %#v, want %d", payload["seed"], seed)
	}
	if payload["frequency_penalty"] != frequencyPenalty {
		t.Fatalf("frequency_penalty = %#v, want %v", payload["frequency_penalty"], frequencyPenalty)
	}
	if payload["presence_penalty"] != presencePenalty {
		t.Fatalf("presence_penalty = %#v, want %v", payload["presence_penalty"], presencePenalty)
	}
}

func TestOpenRouterRequestCarriesAnthropicThinking(t *testing.T) {
	var payload map[string]any
	c := &openRouterClient{
		apiKey:  "test",
		baseURL: "https://openrouter.test",
		httpc: &http.Client{Transport: openRouterRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader(strings.Join([]string{
					`data: {"id":"x","choices":[{"delta":{"content":"ok"},"finish_reason":null}]}`,
					``,
					`data: {"id":"x","choices":[{"delta":{},"finish_reason":"stop"}]}`,
					``,
					`data: [DONE]`,
					``,
				}, "\n"))),
			}, nil
		})},
	}
	topK := 64
	body := &qtypes.AnthropicMessagesRequest{
		Messages:      []qtypes.AnthropicMessage{{Role: "user", Content: "think"}},
		MaxTokens:     8,
		StopSequences: []string{"END"},
		TopK:          &topK,
		Thinking:      map[string]any{"type": "enabled", "budget_tokens": 1024},
		Metadata:      map[string]any{"user_id": "user-123"},
	}
	var out bytes.Buffer

	if err := c.InvokeStreaming(
		t.Context(),
		&qtypes.OpenAIChatRequest{Model: "anthropic/claude-3-5-sonnet"},
		body,
		&out,
	); err != nil {
		t.Fatalf("InvokeStreaming: %v", err)
	}

	if payload["model"] != "anthropic/claude-3.5-sonnet" {
		t.Fatalf("model = %#v", payload["model"])
	}
	thinking, ok := payload["thinking"].(map[string]any)
	if !ok {
		t.Fatalf("thinking = %#v, want object", payload["thinking"])
	}
	if thinking["type"] != "enabled" || thinking["budget_tokens"] != float64(1024) {
		t.Fatalf("thinking = %#v", thinking)
	}
	if payload["top_k"] != float64(topK) {
		t.Fatalf("top_k = %#v, want %d", payload["top_k"], topK)
	}
	metadata, ok := payload["metadata"].(map[string]any)
	if !ok || metadata["user_id"] != "user-123" {
		t.Fatalf("metadata = %#v, want user_id", payload["metadata"])
	}
	stop, ok := payload["stop"].([]any)
	if !ok || len(stop) != 1 || stop[0] != "END" {
		t.Fatalf("stop = %#v", payload["stop"])
	}
	if _, ok := payload["max_tokens"]; ok {
		t.Fatalf("max_tokens present despite MaxTokensExplicit=false: %#v", payload["max_tokens"])
	}
}

func TestOpenRouterAnthropicTemperatureGuard(t *testing.T) {
	invoke := func(t *testing.T, model string, temp float64) map[string]any {
		t.Helper()
		var payload map[string]any
		c := &openRouterClient{
			apiKey:  "test",
			baseURL: "https://openrouter.test",
			httpc: &http.Client{Transport: openRouterRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					return nil, err
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					return nil, err
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
					Body: io.NopCloser(strings.NewReader(strings.Join([]string{
						`data: {"id":"x","choices":[{"delta":{},"finish_reason":"stop"}]}`,
						``,
						`data: [DONE]`,
						``,
					}, "\n"))),
				}, nil
			})},
		}
		body := &qtypes.AnthropicMessagesRequest{
			Messages:    []qtypes.AnthropicMessage{{Role: "user", Content: "hello"}},
			MaxTokens:   8,
			Temperature: &temp,
		}
		if err := c.InvokeStreaming(t.Context(), &qtypes.OpenAIChatRequest{Model: model}, body, &bytes.Buffer{}); err != nil {
			t.Fatalf("InvokeStreaming: %v", err)
		}
		return payload
	}

	payload := invoke(t, "anthropic/claude-3-5-sonnet", 1.8)
	if payload["model"] != "anthropic/claude-3.5-sonnet" {
		t.Fatalf("model = %#v", payload["model"])
	}
	if payload["temperature"] != 1.0 {
		t.Fatalf("temperature = %#v, want clamped 1.0", payload["temperature"])
	}

	for _, model := range []string{
		"anthropic/claude-opus-4.7",
		"anthropic/claude-opus-4.7:floor",
		"anthropic/claude-opus-4.7:extended",
		"anthropic/claude-opus-4.8:nitro",
	} {
		opusPayload := invoke(t, model, 0.5)
		if _, ok := opusPayload["temperature"]; ok {
			t.Fatalf("opus temperature present for %s: %#v", model, opusPayload["temperature"])
		}
	}
}

func TestOpenRouterAllowFallbacksFalseStopsAtFirstModel(t *testing.T) {
	calls := 0
	allowFallbacks := false
	c := &openRouterClient{
		apiKey:  "test",
		baseURL: "https://openrouter.test",
		httpc: &http.Client{Transport: openRouterRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"busy"}}`)),
			}, nil
		})},
	}
	err := c.InvokeStreaming(
		t.Context(),
		&qtypes.OpenAIChatRequest{
			Model:    "openai/gpt-4o-mini",
			Models:   []string{"anthropic/claude-3-5-sonnet"},
			Provider: &qtypes.ProviderRouting{AllowFallbacks: &allowFallbacks},
		},
		&qtypes.AnthropicMessagesRequest{MaxTokens: 4},
		&bytes.Buffer{},
	)

	if err == nil || !strings.Contains(err.Error(), "http 429") {
		t.Fatalf("expected 429 error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestParseProvidersEnv(t *testing.T) {
	cases := map[string][]string{
		"":                         {"google-vertex"},
		"   ":                      {"google-vertex"},
		"anthropic":                {"anthropic"},
		"anthropic, google-vertex": {"anthropic", "google-vertex"},
		"anthropic , amazon-bedrock,google-vertex": {"anthropic", "amazon-bedrock", "google-vertex"},
		",,,": {"google-vertex"}, // all-empty falls back to default
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
