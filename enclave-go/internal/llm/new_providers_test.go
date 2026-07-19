//go:build llm_multi

package llm

import (
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestNewProviderNormalizationAndBYOKPolicy(t *testing.T) {
	t.Parallel()

	if got := normalizeDirectProvider("Digital Ocean"); got != "digitalocean" {
		t.Fatalf("normalize Digital Ocean = %q", got)
	}
	if got := normalizeDirectProvider("Workers AI"); got != "cloudflare-workers-ai" {
		t.Fatalf("normalize Workers AI = %q", got)
	}
	if !isOpenAICompatibleBYOKProvider("chutes") {
		t.Fatal("chutes should support the existing OpenAI-compatible BYOK path")
	}
	if !isOpenAICompatibleBYOKProvider("digitalocean") {
		t.Fatal("digitalocean should support the existing OpenAI-compatible BYOK path")
	}
	if isOpenAICompatibleBYOKProvider("cloudflare-workers-ai") {
		t.Fatal("cloudflare BYOK needs an account id and must stay disabled")
	}
}

func TestMultiClientConstructsAccountScopedCloudflareEndpoint(t *testing.T) {
	t.Parallel()

	client, ok := New(&qtypes.BootstrapData{
		ChutesAPIKey:                 "chutes-key",
		DigitalOceanAPIKey:           "do-key",
		CloudflareWorkersAIAPIKey:    "cf-key",
		CloudflareWorkersAIAccountID: "account-id",
	}).(*multiClient)
	if !ok {
		t.Fatal("New did not return a multiClient")
	}
	if client.chutes.baseURL != "https://llm.chutes.ai/v1" {
		t.Fatalf("chutes baseURL = %q", client.chutes.baseURL)
	}
	if client.digitalocean.baseURL != "https://inference.do-ai.run/v1" {
		t.Fatalf("digitalocean baseURL = %q", client.digitalocean.baseURL)
	}
	if got := client.cloudflareWorkersAI.baseURL; got != "https://api.cloudflare.com/client/v4/accounts/account-id/ai/v1" {
		t.Fatalf("cloudflare baseURL = %q", got)
	}
	if client.cloudflareWorkersAI.apiKey != "cf-key" {
		t.Fatal("cloudflare key was not wired into the client")
	}
}

func TestNewProvidersPreserveAuthorizedUpstreamModelID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		provider string
		model    string
		upstream string
	}{
		{"chutes", "z-ai/glm-5.2", "zai-org/GLM-5.2-TEE"},
		{"digitalocean", "deepseek/deepseek-v4-flash", "deepseek-4-flash"},
		{"cloudflare-workers-ai", "moonshotai/kimi-k3", "moonshotai/kimi-k3"},
	}
	for _, tc := range cases {
		if got := directModelID(tc.provider, tc.model, tc.upstream); got != tc.upstream {
			t.Errorf("directModelID(%q) = %q, want %q", tc.provider, got, tc.upstream)
		}
	}
}
