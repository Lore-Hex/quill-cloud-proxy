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

func TestTinfoilSendsCacheScopeAndRelaysCachedUsage(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, strings.Join([]string{
			`data: {"choices":[{"delta":{"content":"PONG"},"finish_reason":null}]}`,
			``,
			`data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":5,"total_tokens":1005,"prompt_tokens_details":{"cached_tokens":900}}}`,
			``,
			`data: [DONE]`,
			``,
		}, "\n"))
	}))
	defer server.Close()

	client := &openAICompatibleClient{
		provider: "tinfoil",
		baseURL:  server.URL,
		apiKey:   "operator-key",
		httpc:    server.Client(),
	}
	var out bytes.Buffer
	err := client.InvokeStreaming(
		t.Context(),
		&qtypes.OpenAIChatRequest{Model: "z-ai/glm-5.2"},
		&qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "hello"}}},
		&out,
		InvokeOptions{
			Provider:           "tinfoil",
			UpstreamModel:      "glm-5-2",
			ProviderCacheScope: "opaque-workspace-scope",
		},
	)
	if err != nil {
		t.Fatalf("InvokeStreaming: %v", err)
	}
	if got := payload["user_cache_secret"]; got != "opaque-workspace-scope" {
		t.Fatalf("user_cache_secret = %#v", got)
	}
	if !strings.Contains(out.String(), `"cache_read_input_tokens":900`) {
		t.Fatalf("cached usage was not relayed: %s", out.String())
	}
}

func TestCacheScopeIsNeverSentToOtherOpenAICompatibleProviders(t *testing.T) {
	request := buildOpenAICompatibleRequest(
		"openai",
		"gpt-4o-mini",
		&qtypes.OpenAIChatRequest{},
		&qtypes.AnthropicMessagesRequest{},
		nil,
	)
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if strings.Contains(string(body), "user_cache_secret") {
		t.Fatalf("Tinfoil-only cache field leaked: %s", body)
	}
}
