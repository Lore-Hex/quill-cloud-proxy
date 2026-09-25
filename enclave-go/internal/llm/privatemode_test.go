package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestPrivatemodeUsesSharedUsageAndToolTranslation(t *testing.T) {
	defer ConfigurePrivatemode(nil)
	calls := 0
	ConfigurePrivatemode(&http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://privatemode.internal:18489/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer synthetic-key" {
			t.Fatal("request escaped pinned proxy or lost credentials")
		}
		var wire map[string]any
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		if wire["model"] != "gpt-oss-120b" || wire["stream"] != true {
			t.Fatalf("incorrect wire model/stream")
		}
		if salt, _ := wire["cache_salt"].(string); len(salt) != 64 {
			t.Fatal("authorized cache scope missing from encrypted request")
		}
		if wire["reasoning_effort"] != "low" || wire["reasoning"] != nil || wire["thinking"] != nil {
			t.Fatal("reasoning effort was not translated")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(
			"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_test\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n" +
				"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":12,\"total_tokens\":112,\"prompt_tokens_details\":{\"cached_tokens\":80},\"completion_tokens_details\":{\"reasoning_tokens\":5}}}\n\ndata: [DONE]\n\n"))}, nil
	})})
	var out bytes.Buffer
	err := newOpenAICompatible("privatemode", "synthetic-key").InvokeStreaming(t.Context(),
		&qtypes.OpenAIChatRequest{Model: "openai/gpt-oss-120b", Reasoning: map[string]any{"effort": "low"}},
		&qtypes.AnthropicMessagesRequest{MaxTokens: 32, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "synthetic"}}},
		&out, InvokeOptions{Provider: "privatemode", UpstreamModel: "gpt-oss-120b", ProviderCacheScope: "synthetic-workspace"})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"input_tokens":100`, `"output_tokens":12`, `"cache_read_input_tokens":80`, `"reasoning_tokens":5`, `"type":"tool_use"`, `"name":"lookup"`} {
		if !strings.Contains(out.String(), expected) {
			t.Errorf("missing %s", expected)
		}
	}
	if calls != 1 {
		t.Fatalf("unexpected duplicate calls: %d", calls)
	}
}

func TestPrivatemodeFailsClosedBeforeHTTP(t *testing.T) {
	client := newOpenAICompatible("privatemode", "synthetic-key")
	req := &qtypes.OpenAIChatRequest{Model: "openai/gpt-oss-120b"}
	for _, tc := range []struct {
		option  InvokeOptions
		message string
	}{
		{InvokeOptions{Provider: "privatemode", UpstreamModel: "gpt-oss-120b", ProviderAPIKey: "byok"}, "BYOK"},
		{InvokeOptions{Provider: "privatemode", UpstreamModel: "glm-latest"}, "release-pinned"},
		{InvokeOptions{Provider: "privatemode", UpstreamModel: "gpt-oss-120b"}, "attested proxy unavailable"},
	} {
		err := client.InvokeStreaming(context.Background(), req, nil, io.Discard, tc.option)
		if err == nil || !strings.Contains(err.Error(), tc.message) {
			t.Fatalf("got %v, want %s", err, tc.message)
		}
	}
}

func TestPrivatemodeOtherAPIsNeverUsePublicEndpoint(t *testing.T) {
	for _, provider := range []string{"", "privatemode", "openai"} {
		for _, key := range []string{"", "synthetic-byok"} {
			client := newOpenAICompatible("privatemode", "synthetic-key")
			option := InvokeOptions{Provider: provider, ProviderAPIKey: key}
			if _, err := client.InvokeEmbedding(t.Context(), nil, option); err == nil {
				t.Fatal("embedding dispatch did not fail closed")
			}
			if _, err := client.InvokeDecide(t.Context(), nil, option); err == nil {
				t.Fatal("decide dispatch did not fail closed")
			}
		}
	}
}

func TestPrivatemodeReasoningAndCacheScope(t *testing.T) {
	for _, tc := range []struct {
		model, effort string
		valid         bool
	}{
		{"gpt-oss-120b", "", true}, {"gpt-oss-120b", "medium", true},
		{"gpt-oss-120b", "max", false}, {"gpt-oss-120b", "none", false},
		{"glm-5.3", "max", true}, {"glm-5.3-flash", "low", true},
		{"glm-5.3", "medium", false}, {"glm-5.3-flash", "none", false},
	} {
		req := &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"effort": tc.effort}}
		wire := openAICompatibleRequest{Model: tc.model, Thinking: map[string]any{"budget_tokens": 1024}}
		err := preparePrivatemodeWire(req, nil, &wire, "opaque-workspace-one")
		if (err == nil) != tc.valid {
			t.Fatalf("model=%s effort=%s valid=%v error=%v", tc.model, tc.effort, tc.valid, err)
		}
		if tc.valid && (wire.ReasoningEffort != tc.effort || wire.Thinking != nil || wire.Reasoning != nil || len(wire.CacheSalt) != 64) {
			t.Fatal("lost reasoning normalization or workspace salt")
		}
	}
	first, same, other, absent := openAICompatibleRequest{}, openAICompatibleRequest{}, openAICompatibleRequest{}, openAICompatibleRequest{}
	for scope, wire := range map[string]*openAICompatibleRequest{"one": &first, " one ": &same, "two": &other, "": &absent} {
		if err := preparePrivatemodeWire(nil, nil, wire, scope); err != nil {
			t.Fatal(err)
		}
	}
	if first.CacheSalt != same.CacheSalt || first.CacheSalt == other.CacheSalt || absent.CacheSalt != "" {
		t.Fatal("cache isolation failed")
	}
	off := &qtypes.OpenAIChatRequest{Reasoning: map[string]any{"enabled": false}}
	if err := preparePrivatemodeWire(off, nil, &first, "one"); err == nil {
		t.Fatal("off silently accepted")
	}
	native := &qtypes.AnthropicMessagesRequest{NativeContent: true, Thinking: map[string]any{"budget_tokens": 1024}}
	if err := preparePrivatemodeWire(nil, native, &first, "one"); err == nil {
		t.Fatal("unrepresentable budget accepted")
	}
}

func TestPrivatemodeIncompleteStreamsAreNotSuccessful(t *testing.T) {
	finish := `data: {"choices":[{"delta":{"content":"partial"},"finish_reason":"stop"}]}` + "\n\n"
	usage := `data: {"choices":[],"usage":{"prompt_tokens":20,"completion_tokens":4}}` + "\n\n"
	for _, stream := range []string{finish, finish + "data: [DONE]\n\n", finish + usage, "data: broken\n\n"} {
		var out bytes.Buffer
		if err := translateOpenAIStreamToAnthropicForProvider(strings.NewReader(stream), &out, "privatemode"); err == nil {
			t.Fatal("incomplete stream treated as success")
		}
		if strings.Contains(out.String(), "message_stop") {
			t.Fatal("success terminator emitted")
		}
	}
}
