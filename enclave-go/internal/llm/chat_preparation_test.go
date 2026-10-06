package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type preparationTransport func(*http.Request) (*http.Response, error)

func (f preparationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Each row crosses stream on/off, explicit/implicit cap, and all ten request
// variants. The frozen builder is from 4a4f0695; actual dispatch is intercepted
// at the HTTP boundary to detect even a one-byte rewrite after preparation.
func TestChatPreparationDifferential(t *testing.T) {
	routes := [][2]string{
		{"fixture-provider", "fixture-text"}, {"openai", "gpt-4o"}, {"openai", "gpt-5.5"},
		{"openai", "o3"}, {"openai", "gpt-6-astra"}, {"kimi", "kimi-k2.5"},
		{"novita", "moonshotai/kimi-k2.6"}, {"azure", "kimi-k2-5"}, {"azure", "kimi-k2-6"},
		{"azure", "kimi-k3"}, {"azure", "codestral-2501"}, {"meta", "muse-spark"},
		{"google-ai-studio", "gemini-2.5-flash"}, {"google-ai-studio", "gemini-3-flash-preview"},
		{"gemini", "gemini-3.7-flash"}, {"google-ai-studio", "gemini-3.7-pro"},
		{"engy", "qwen3.6-35b-a3b"}, {"perplexity", "sonar"}, {"tinfoil", "llama"},
		{"neurometric", "neurometric/structured-decisions"}, {"neurometric", "other"},
		{"tencent", "minimax-m3"}, {"tencent", "kimi-k3"}, {"tencent", "kimi-k2.8-preview"},
		{"tencent", "glm-5.3"}, {"deepseek", "deepseek-chat"}, {"zai", "glm-4.7"},
		{"privatemode", "gpt-oss-120b"}, {"mistral", "mistral-large"}, {"alibaba", "qwen"},
	}
	variants := []string{"implicit", "explicit", "system", "unicode", "empty", "huge", "effort", "off", "tools", "thinking"}
	count := 0
	for _, route := range routes {
		for _, stream := range []bool{false, true} {
			for _, capSet := range []bool{false, true} {
				for _, variant := range variants {
					count++
					t.Run(fmt.Sprintf("%s/%s/stream=%t/cap=%t/%s", route[0], route[1], stream, capSet, variant), func(t *testing.T) {
						req := &qtypes.OpenAIChatRequest{Model: route[1], Stream: stream, Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "hello"}}}
						if capSet {
							n := 512
							req.MaxTokens = &n
						}
						f, i, b := 0.25, 2, true
						switch variant {
						case "explicit":
							req.Temperature = &f
							req.TopP = &f
							req.TopK = &i
							req.TopA = &f
							req.MinP = &f
							req.RepetitionPenalty = &f
							req.Seed = &i
							req.FrequencyPenalty = &f
							req.PresencePenalty = &f
							req.LogitBias = map[string]float64{"2": -1, "1": 1}
							req.Logprobs = &b
							req.TopLogprobs = &i
							req.Stop = []string{"STOP", "終"}
							req.ServiceTier = " priority "
							req.StreamOptions = &qtypes.ChatStreamOptions{IncludeUsage: false}
							req.Prediction = map[string]any{"type": "content", "content": "hello"}
							req.PromptCacheKey = "cache"
							req.PromptCacheOptions = map[string]any{"ttl": 10}
							req.ResponseFormat = map[string]any{"type": "json_object"}
						case "system":
							req.Messages = append([]qtypes.OpenAIChatMessage{{Role: "system", Content: "prefix"}, {Role: "system", Content: "addition"}}, req.Messages...)
						case "unicode":
							req.Messages[0].Content = "雪🙂<>&\u2028\n\"\\"
						case "empty":
							req.Messages = append(req.Messages, qtypes.OpenAIChatMessage{Role: "user", Content: ""})
						case "huge":
							req.Messages[0].Content = strings.Repeat("<", 64<<10)
						case "effort":
							req.Reasoning = map[string]any{"effort": "minimal", "summary": "auto"}
						case "off":
							req.Reasoning = map[string]any{"enabled": false}
						case "tools":
							req.Tools = []any{map[string]any{"type": "function", "function": map[string]any{"name": "lookup", "parameters": map[string]any{"type": "object"}}}}
							req.ToolChoice = "auto"
							req.ParallelTools = &b
							req.Reasoning = map[string]any{"enabled": true}
						case "thinking":
							req.ReasoningEffort = "high"
						}
						body, err := adapter.ToAnthropic(req, req.Model)
						if err != nil {
							t.Fatal(err)
						}
						if variant == "thinking" {
							body.NativeContent = true
							body.Thinking = map[string]any{"type": "enabled", "budget_tokens": 1024}
						}
						msgs, err := openAICompatibleMessagesWithFetchedImages(context.Background(), body)
						if err != nil {
							t.Fatal(err)
						}
						model := directModelID(route[0], req.Model, route[1])
						before, _ := json.Marshal([]any{req, body, msgs})
						want, werr := frozenPrepareChatRequest(route[0], model, req, body, msgs, "fixed-scope")
						opts := ChatPreparationOptions{ProviderCacheScope: "fixed-scope"}
						if route[0] == "privatemode" {
							opts.privateWire = &openAICompatibleRequest{Model: model}
							err = preparePrivatemodeWire(req, body, opts.privateWire, "fixed-scope")
						}
						var got PreparedChatRequest
						var gerr error
						if err != nil {
							gerr = err
						} else {
							got, gerr = PrepareChatRequest(route[0], route[1], req, body, msgs, opts)
						}
						if fmt.Sprint(gerr) != fmt.Sprint(werr) || !reflect.DeepEqual(got, want) {
							t.Fatalf("preparation differs: %s / %s\n%s\n%s", gerr, werr, got.Bytes, want.Bytes)
						}
						after, _ := json.Marshal([]any{req, body, msgs})
						if !bytes.Equal(before, after) {
							t.Fatal("input mutated")
						}
						reached := false
						sentinel := errors.New("captured wire")
						client := &http.Client{Transport: preparationTransport(func(r *http.Request) (*http.Response, error) {
							reached = true
							wire, readErr := io.ReadAll(r.Body)
							if readErr != nil {
								t.Fatal(readErr)
							}
							if !bytes.Equal(wire, want.Bytes) || r.URL.Path != want.Path {
								t.Fatalf("ordinary wire differs: %s", wire)
							}
							return nil, sentinel
						})}
						err = invokeOpenAICompatibleStreamingWithClientOptions(context.Background(), client, route[0], "https://fixture.invalid", "test-key", req, body, io.Discard, route[1], openAICompatibleInvocationOptions{providerCacheScope: "fixed-scope"})
						if werr == nil && (!reached || !errors.Is(err, sentinel)) {
							t.Fatal("dispatch did not send prepared wire", err)
						}
						if werr != nil && (reached || fmt.Sprint(err) != fmt.Sprint(werr)) {
							t.Fatal("dispatch error differs", err, werr)
						}
					})
				}
			}
		}
	}
	t.Logf("byte-equality matrix: %d cases", count)
}

func TestChatPreparationErrors(t *testing.T) {
	for _, tc := range []struct {
		name, provider, model string
		req                   qtypes.OpenAIChatRequest
	}{
		{"missing_model", "fixture-provider", "", qtypes.OpenAIChatRequest{}},
		{"unresolved_private_cache", "privatemode", "gpt-oss-120b", qtypes.OpenAIChatRequest{}},
		{"responses_invalid_tool", "openai", "gpt-6-astra", qtypes.OpenAIChatRequest{Tools: []any{true}}},
		{"marshal", "openai", "gpt-4o", qtypes.OpenAIChatRequest{Stop: make(chan int)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PrepareChatRequest(tc.provider, tc.model, &tc.req, nil, []ChatMessage{{Role: "user", Content: "hello"}}, ChatPreparationOptions{})
			if err == nil || len(got.Bytes) > 0 {
				t.Fatal("accepted invalid preparation", got, err)
			}
		})
	}
}

func TestChatPreparationNilRequest(t *testing.T) {
	got, err := PrepareChatRequest("fixture-provider", "fixture-text", nil, nil, nil, ChatPreparationOptions{})
	want, werr := frozenPrepareChatRequest("fixture-provider", "fixture-text", nil, nil, nil, "")
	if err != nil || werr != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err, werr)
	}
}

// Keep a full MiB escaping regression without repeating it for every provider
// under the race detector; the matrix separately crosses size with every route.
func TestChatPreparationHugeContent(t *testing.T) {
	req := &qtypes.OpenAIChatRequest{Model: "fixture-text", Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: strings.Repeat("<", 1<<20)}}}
	body, err := adapter.ToAnthropic(req, req.Model)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := openAICompatibleMessagesWithFetchedImages(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	want, err := frozenPrepareChatRequest("fixture-provider", req.Model, req, body, msgs, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := PrepareChatRequest("fixture-provider", req.Model, req, body, msgs, ChatPreparationOptions{})
	if err != nil || !bytes.Equal(got.Bytes, want.Bytes) {
		t.Fatal("large escaped wire differs", err)
	}
	reached := false
	sentinel := errors.New("captured large wire")
	client := &http.Client{Transport: preparationTransport(func(r *http.Request) (*http.Response, error) {
		reached = true
		wire, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(wire, want.Bytes) {
			t.Fatal("large ordinary wire differs")
		}
		return nil, sentinel
	})}
	err = invokeOpenAICompatibleStreamingWithClientOptions(context.Background(), client, "fixture-provider", "https://fixture.invalid", "test-key", req, body, io.Discard, req.Model, openAICompatibleInvocationOptions{})
	if !reached || !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}
