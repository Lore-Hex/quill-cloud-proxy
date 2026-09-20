//go:build llm_multi

package llm

import "testing"

func TestDirectWaveKeepsIndependentCredentialsAndNativeIDs(t *testing.T) {
	keys := map[string]string{
		"redpill": "redpill-test", "meta-direct": "meta-test",
		"general-compute": "general-test", "infomaniak": "infomaniak-test",
	}
	clients := newBootstrapDirectClients(keys)
	for slug, key := range keys {
		client := clients[slug]
		if client == nil || client.apiKey != key || client.provider != slug {
			t.Fatalf("%s did not receive its own credential", slug)
		}
		if directModelID(slug, "canonical/model", "Exact-Native-Model") != "Exact-Native-Model" {
			t.Fatalf("%s rewrote an authorized native model", slug)
		}
		if isOpenAICompatibleBYOKProvider(slug) {
			t.Fatalf("%s must be credits-only", slug)
		}
	}
	if normalizeDirectProvider("red-pill") != "redpill" || normalizeDirectProvider("phala") != "phala" {
		t.Fatal("Redpill and Phala must not share a provider identity")
	}
	if clients["meta-direct"].baseURL != "https://api.meta.ai/v1" {
		t.Fatal("Meta direct must not use OpenRouter")
	}
	if clients["infomaniak"].baseURL != "https://api.infomaniak.com/2/ai/111565/openai/v1" {
		t.Fatal("Infomaniak must use the verified account-scoped inference path")
	}
	if len(newBootstrapDirectClients(map[string]string{"redpill": "", "privatemode": "key", "swisscom": "key"})) != 0 {
		t.Fatal("missing credentials and unsupported transports must stay disabled")
	}
}
