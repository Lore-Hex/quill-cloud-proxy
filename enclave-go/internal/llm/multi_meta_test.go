//go:build llm_multi

package llm

import (
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
