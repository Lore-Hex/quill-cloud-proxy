//go:build llm_multi

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAzureOpenAIUsesAPIKeyAndAuthorizedDeploymentName(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("api-key"); got != "azure-secret" {
			t.Errorf("api-key = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization must be omitted, got %q", got)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if got := payload["model"]; got != "deepseek-v4-flash" {
			t.Errorf("model = %#v", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	var out bytes.Buffer
	err := invokeOpenAICompatibleStreamingWithClient(
		context.Background(),
		server.Client(),
		"azure",
		server.URL,
		"azure-secret",
		&qtypes.OpenAIChatRequest{Model: "deepseek/deepseek-v4-flash"},
		&qtypes.AnthropicMessagesRequest{
			Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}},
		},
		&out,
		"deepseek-v4-flash",
	)
	if err != nil {
		t.Fatalf("invoke Azure OpenAI-compatible model: %v", err)
	}
	if !strings.Contains(out.String(), `"text":"PONG"`) {
		t.Fatalf("translated stream lost PONG: %s", out.String())
	}
}

func TestAzureAnthropicUsesNativeMessagesAndDeploymentName(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "azure-secret" {
			t.Errorf("x-api-key = %q", got)
		}
		if got := r.Header.Get("anthropic-version"); got != anthropicVersionHeader {
			t.Errorf("anthropic-version = %q", got)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if got := payload["model"]; got != "claude-opus-5" {
			t.Errorf("model = %#v", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: content_block_delta\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"PONG\"}}\n\n")
	}))
	defer server.Close()

	client := newAnthropicAt("azure", server.URL, "azure-secret", true)
	client.httpc = server.Client()
	var out bytes.Buffer
	err := client.InvokeStreaming(
		context.Background(),
		&qtypes.OpenAIChatRequest{Model: "anthropic/claude-opus-5"},
		&qtypes.AnthropicMessagesRequest{
			MaxTokens: 16,
			Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}},
		},
		&out,
		InvokeOptions{Provider: "azure", UpstreamModel: "claude-opus-5"},
	)
	if err != nil {
		t.Fatalf("invoke Azure Anthropic model: %v", err)
	}
	if !strings.Contains(out.String(), "PONG") {
		t.Fatalf("native Anthropic stream lost PONG: %s", out.String())
	}
}

func TestAzureProviderRoutingContract(t *testing.T) {
	t.Parallel()

	if got := normalizeDirectProvider("Microsoft Foundry"); got != "azure" {
		t.Fatalf("normalizeDirectProvider = %q", got)
	}
	if got := directBaseURL("azure"); got != "https://trustedrouter-foundry-eastus2.openai.azure.com/openai/v1" {
		t.Fatalf("directBaseURL(azure) = %q", got)
	}
	if got := directModelID(
		"azure",
		"anthropic/claude-opus-5",
		"claude-opus-5",
	); got != "claude-opus-5" {
		t.Fatalf("directModelID(azure) = %q", got)
	}
	if isOpenAICompatibleBYOKProvider("azure") {
		t.Fatal("Azure must remain managed-credits-only")
	}
}

func TestAzureOpenAIReasoningModelsUseCompletionTokenField(t *testing.T) {
	t.Parallel()

	temperature := 0.0
	maxTokens := 32
	req := buildOpenAICompatibleRequest(
		"azure",
		"gpt-5.4-mini",
		&qtypes.OpenAIChatRequest{},
		&qtypes.AnthropicMessagesRequest{
			MaxTokens:         maxTokens,
			MaxTokensExplicit: true,
			Temperature:       &temperature,
		},
		nil,
	)
	if req.MaxCompletionTokens != maxTokens {
		t.Fatalf("max_completion_tokens = %d, want %d", req.MaxCompletionTokens, maxTokens)
	}
	if req.MaxTokens != 0 {
		t.Fatalf("max_tokens = %d, want omitted", req.MaxTokens)
	}
	if req.Temperature != nil {
		t.Fatal("Azure-hosted GPT 5 temperature must be omitted")
	}
}

func TestAzureCodestralOmitsUnsupportedStreamOptions(t *testing.T) {
	t.Parallel()

	req := buildOpenAICompatibleRequest(
		"azure",
		"codestral-2501",
		&qtypes.OpenAIChatRequest{},
		&qtypes.AnthropicMessagesRequest{},
		nil,
	)
	if req.StreamOptions != nil {
		t.Fatal("Azure Codestral must omit unsupported stream_options")
	}
	if !supportsStreamUsageOption("azure", "gpt-5.4-mini") {
		t.Fatal("other Azure models must retain stream usage requests")
	}
}
