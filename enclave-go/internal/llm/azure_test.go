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
	"sync/atomic"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAzureOpenAIUsesAPIKeyAndAuthorizedDeploymentName(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/chat/completions" {
			t.Errorf("path = %q", got)
		}
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
		if got := r.URL.Path; got != "/messages" {
			t.Errorf("path = %q", got)
		}
		if got := r.Header.Get("x-api-key"); got != "azure-secret" {
			t.Errorf("x-api-key = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization must be omitted, got %q", got)
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

	client := newAnthropicAt("azure", server.URL+"/messages", "azure-secret", true)
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

	client := newAzure("azure-key")
	if client.openAI.apiKey != "azure-key" || client.anthropic.apiKey != "azure-key" {
		t.Fatal("Azure key was not wired into both protocol clients")
	}
	for _, alias := range []string{"Azure", "Azure AI", "Azure AI Foundry", "Microsoft Foundry"} {
		if got := normalizeDirectProvider(alias); got != "azure" {
			t.Errorf("normalizeDirectProvider(%q) = %q", alias, got)
		}
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
		t.Fatal("Azure must remain managed-credits-only until account-scoped BYOK endpoints are implemented")
	}
	if !azureUsesAnthropicWire("", "anthropic/claude-opus-5") {
		t.Fatal("canonical Claude fallback must select Azure's native Anthropic wire")
	}
	if azureUsesAnthropicWire("gpt-5-4-mini", "openai/gpt-5.4-mini") {
		t.Fatal("OpenAI-family Azure deployment selected Anthropic wire")
	}
}

func TestAzureOpenAIReasoningModelsUseCompletionTokenField(t *testing.T) {
	t.Parallel()

	temperature := 0.0
	maxTokens := 32
	req := buildOpenAICompatibleRequest(
		"azure",
		"gpt-5-4-mini",
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
	if !supportsStreamUsageOption("azure", "gpt-5-4-mini") {
		t.Fatal("other Azure models must retain stream usage requests")
	}
}

func TestAzureOpenAIRedirectCannotReplayAPIKey(t *testing.T) {
	t.Parallel()

	var redirectRequests atomic.Int32
	var sinkRequests atomic.Int32
	var sinkCredential atomic.Value
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sinkRequests.Add(1)
		sinkCredential.Store(r.Header.Get("api-key"))
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectRequests.Add(1)
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	client := newAzure("azure-secret")
	client.openAI.baseURL = redirector.URL
	// Keep the redirect policy installed by newAzure while replacing only the
	// cloud-specific transport, so this remains runnable in cloud_aws tests.
	client.openAI.httpc.Transport = redirector.Client().Transport
	err := client.InvokeStreaming(
		context.Background(),
		&qtypes.OpenAIChatRequest{Model: "openai/gpt-5.4-mini"},
		&qtypes.AnthropicMessagesRequest{},
		io.Discard,
		InvokeOptions{Provider: "azure", UpstreamModel: "gpt-5-4-mini"},
	)
	if status, ok := HTTPStatusFromError(err); !ok || status != http.StatusTemporaryRedirect {
		t.Fatalf("redirect status = (%d, %v), error = %v", status, ok, err)
	}
	if got := redirectRequests.Load(); got != 1 {
		t.Fatalf("redirect authority requests = %d, want 1", got)
	}
	if got := sinkRequests.Load(); got != 0 {
		t.Fatalf("redirect sink received %d requests, want 0", got)
	}
	if credential, _ := sinkCredential.Load().(string); credential != "" {
		t.Fatalf("redirect sink received api-key %q", credential)
	}
}

func TestAzureAnthropicRedirectCannotReplayAPIKey(t *testing.T) {
	t.Parallel()

	var redirectRequests atomic.Int32
	var sinkRequests atomic.Int32
	var sinkCredential atomic.Value
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sinkRequests.Add(1)
		sinkCredential.Store(r.Header.Get("x-api-key"))
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectRequests.Add(1)
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	client := newAzure("azure-secret")
	client.anthropic.url = redirector.URL
	// Keep the redirect policy installed by newAzure while replacing only the
	// cloud-specific transport, so this remains runnable in cloud_aws tests.
	client.anthropic.httpc.Transport = redirector.Client().Transport
	err := client.InvokeStreaming(
		context.Background(),
		&qtypes.OpenAIChatRequest{Model: "anthropic/claude-opus-5"},
		&qtypes.AnthropicMessagesRequest{
			MaxTokens: 16,
			Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "PONG"}},
		},
		io.Discard,
		InvokeOptions{Provider: "azure", UpstreamModel: "claude-opus-5"},
	)
	if status, ok := HTTPStatusFromError(err); !ok || status != http.StatusTemporaryRedirect {
		t.Fatalf("redirect status = (%d, %v), error = %v", status, ok, err)
	}
	if got := redirectRequests.Load(); got != 1 {
		t.Fatalf("redirect authority requests = %d, want 1", got)
	}
	if got := sinkRequests.Load(); got != 0 {
		t.Fatalf("redirect sink received %d requests, want 0", got)
	}
	if credential, _ := sinkCredential.Load().(string); credential != "" {
		t.Fatalf("redirect sink received x-api-key %q", credential)
	}
}
