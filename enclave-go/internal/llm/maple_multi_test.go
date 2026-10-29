//go:build llm_multi

package llm

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/maple"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestMapleDispatcherCannotUsePlainHTTPOrBYOK(t *testing.T) {
	for _, key := range []string{"", "managed-key"} {
		m := &multiClient{direct: newBootstrapDirectClients(map[string]string{"maple": key})}
		if c := m.direct["maple"]; c != nil {
			c.httpc = &http.Client{Transport: byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("Maple fell through to ordinary HTTPS")
				return nil, nil
			})}
		}
		for _, option := range []InvokeOptions{
			{Provider: "maple", ProviderAPIKey: "byok", UpstreamModel: maple.Model},
			{Provider: "maple", UpstreamModel: "unreviewed-model"},
		} {
			err := m.InvokeStreaming(context.Background(), &qtypes.OpenAIChatRequest{},
				&qtypes.AnthropicMessagesRequest{}, io.Discard, option)
			if err == nil || !strings.Contains(err.Error(), "maple") {
				t.Fatalf("Maple dispatch did not fail closed: %v", err)
			}
		}
	}
}

func TestMapleRejectsGenericTransportsAndOtherModalities(t *testing.T) {
	httpc := &http.Client{Transport: byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("Maple reached ordinary HTTPS")
		return nil, nil
	})}
	ctx := context.Background()
	for _, provider := range []string{"maple", "openai"} {
		c := newOpenAICompatibleAt(provider, "https://enclave.trymaple.ai/v1", "managed")
		c.httpc = httpc
		c.httpcGetter = func() (*http.Client, error) {
			t.Fatal("unsupported Maple request resolved an HTTP client")
			return nil, nil
		}
		if provider == "maple" {
			if client, err := c.resolveHTTPClient(); err == nil || client != nil {
				t.Fatal("Maple resolved an ordinary HTTP client")
			}
		}
		for _, option := range []InvokeOptions{
			{Provider: "maple"},
			{Provider: "maple", ProviderAPIKey: "byok", UsageType: "BYOK"},
		} {
			if response, err := c.InvokeEmbedding(ctx, nil, option); err == nil || response != nil {
				t.Fatal("Maple embeddings did not fail closed")
			}
			if response, err := c.InvokeDecide(ctx, nil, option); err == nil || response != nil {
				t.Fatal("Maple decisions did not fail closed")
			}
		}
		if provider == "maple" {
			if _, err := c.InvokeEmbedding(ctx, nil, InvokeOptions{Provider: "openai"}); err == nil {
				t.Fatal("Maple embeddings accepted a provider override")
			}
			if _, err := c.InvokeDecide(ctx, nil, InvokeOptions{Provider: "openai"}); err == nil {
				t.Fatal("Maple decisions accepted a provider override")
			}
		}
	}
	for _, provider := range []string{"maple", " MAPLE "} {
		err := invokeOpenAICompatibleStreamingWithClientOptions(ctx, httpc, provider,
			"https://enclave.trymaple.ai/v1", "managed", nil, nil, io.Discard,
			maple.Model, openAICompatibleInvocationOptions{})
		if err == nil {
			t.Fatal("generic Maple chat transport did not fail closed")
		}
		if _, err := invokeOpenAICompatibleEmbeddings(ctx, httpc, provider,
			"https://enclave.trymaple.ai/v1", "managed", nil, maple.Model); err == nil {
			t.Fatal("generic Maple embeddings transport did not fail closed")
		}
		if isOpenAICompatibleBYOKProvider(provider) {
			t.Fatal("Maple unexpectedly supports BYOK")
		}
	}
}
