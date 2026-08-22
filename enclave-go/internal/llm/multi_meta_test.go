//go:build llm_multi

package llm

import (
	"bytes"
	"context"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestMultiClientWiresMetaThroughOpenRouterKey(t *testing.T) {
	client, ok := New(&qtypes.BootstrapData{OpenRouterAPIKey: "sk-or-test"}).(*multiClient)
	if !ok {
		t.Fatal("New did not return multiClient")
	}
	if client.meta == nil {
		t.Fatal("Meta client is nil")
	}
	if client.meta.provider != "meta" {
		t.Fatalf("provider = %q, want meta", client.meta.provider)
	}
	if client.meta.baseURL != "https://openrouter.ai/api/v1" {
		t.Fatalf("baseURL = %q", client.meta.baseURL)
	}
	if client.meta.apiKey != "sk-or-test" {
		t.Fatal("Meta client did not receive the OpenRouter inference key")
	}
}

func TestMultiClientWiresExclusiveRouteThroughOpenRouterKey(t *testing.T) {
	client, ok := New(&qtypes.BootstrapData{OpenRouterAPIKey: "sk-or-test"}).(*multiClient)
	if !ok {
		t.Fatal("New did not return multiClient")
	}
	if client.openRouterExclusive == nil {
		t.Fatal("OpenRouter-exclusive client is nil")
	}
	if client.openRouterExclusive.provider != "openrouter-exclusive" {
		t.Fatalf("provider = %q, want openrouter-exclusive", client.openRouterExclusive.provider)
	}
	if client.openRouterExclusive.baseURL != "https://openrouter.ai/api/v1" {
		t.Fatalf("baseURL = %q", client.openRouterExclusive.baseURL)
	}
	if client.openRouterExclusive.apiKey != "sk-or-test" {
		t.Fatal("exclusive client did not receive the OpenRouter inference key")
	}
	if got := DirectModelID(
		"openrouter-exclusive",
		"stealth/ox-alpha",
		"stealth/ox-alpha",
	); got != "stealth/ox-alpha" {
		t.Fatalf("DirectModelID = %q, want stealth/ox-alpha", got)
	}
	if !openRouterExclusiveModelAllowed("stealth/ox-alpha", "stealth/ox-alpha") {
		t.Fatal("Ox Alpha should be allowlisted")
	}
	if openRouterExclusiveModelAllowed("openai/gpt-5.5", "openai/gpt-5.5") {
		t.Fatal("an arbitrary OpenRouter model must not be allowlisted")
	}
	err := client.InvokeStreaming(
		context.Background(),
		&qtypes.OpenAIChatRequest{Model: "openai/gpt-5.5"},
		&qtypes.AnthropicMessagesRequest{},
		&bytes.Buffer{},
		InvokeOptions{
			Provider:      "openrouter-exclusive",
			UpstreamModel: "openai/gpt-5.5",
		},
	)
	if err == nil || !strings.Contains(err.Error(), "model is not allowlisted") {
		t.Fatalf("arbitrary OpenRouter model error = %v", err)
	}
}
