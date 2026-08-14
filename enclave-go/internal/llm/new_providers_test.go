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
	for _, provider := range []string{"inceptron", "morph", "atlas-cloud", "streamlake", "neurometric", "pearl", "engy", "databricks", "zero-g", "alibaba"} {
		if isOpenAICompatibleBYOKProvider(provider) {
			t.Errorf("%s must use only the operator-key prepaid path", provider)
		}
	}
}

func TestMultiClientConstructsOpenAICompatibleProviderEndpoints(t *testing.T) {
	t.Parallel()

	client, ok := New(&qtypes.BootstrapData{
		ChutesAPIKey:                 "chutes-key",
		DigitalOceanAPIKey:           "do-key",
		CloudflareWorkersAIAPIKey:    "cf-key",
		CloudflareWorkersAIAccountID: "account-id",
		InceptronAPIKey:              "inceptron-key",
		MorphAPIKey:                  "morph-key",
		AtlasCloudAPIKey:             "atlas-key",
		StreamLakeAPIKey:             "streamlake-key",
		NeurometricAPIKey:            "neurometric-key",
		PearlAPIKey:                  "pearl-key",
		EngyAPIKey:                   "engy-key",
		DatabricksToken:              "databricks-token",
		DatabricksHost:               "dbc-1234.cloud.databricks.com",
		ZeroGAPIKey:                  "zero-g-key",
		AlibabaAPIKey:                "alibaba-key",
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
	if client.zeroG.baseURL != "https://router-api.0g.ai/v1" {
		t.Fatalf("zero-g baseURL = %q", client.zeroG.baseURL)
	}
	if client.zeroG.apiKey != "zero-g-key" {
		t.Fatal("zero-g key was not wired into the dual-format client")
	}
	wantClients := map[string]struct {
		client  *openAICompatibleClient
		baseURL string
		apiKey  string
	}{
		"inceptron":   {client.inceptron, "https://api.inceptron.io/v1", "inceptron-key"},
		"morph":       {client.morph, "https://api.morphllm.com/v1", "morph-key"},
		"atlas-cloud": {client.atlasCloud, "https://api.atlascloud.ai/v1", "atlas-key"},
		"streamlake":  {client.streamLake, "https://vanchin.streamlake.ai/api/gateway/v1/endpoints", "streamlake-key"},
		"neurometric": {client.neurometric, "https://wharf.neurometric.ai/v1", "neurometric-key"},
		"pearl":       {client.pearl, "https://inference.pearlresearch.ai/v1", "pearl-key"},
		"engy":        {client.engy, "https://api.engy.ai/v1", "engy-key"},
		"databricks": {
			client.databricks,
			"https://dbc-1234.cloud.databricks.com/serving-endpoints",
			"databricks-token",
		},
		"alibaba": {
			client.alibaba,
			"https://ws-el6e4bpnggpx7g88.eu-central-1.maas.aliyuncs.com/compatible-mode/v1",
			"alibaba-key",
		},
	}
	for provider, want := range wantClients {
		if want.client.baseURL != want.baseURL {
			t.Errorf("%s baseURL = %q, want %q", provider, want.client.baseURL, want.baseURL)
		}
		if want.client.apiKey != want.apiKey {
			t.Errorf("%s operator key was not wired into the client", provider)
		}
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
		{"inceptron", "moonshotai/kimi-k2.7-code", "moonshotai/Kimi-K2.7-Code"},
		{"morph", "z-ai/glm-5.2", "morph-glm52-744b"},
		{"atlas-cloud", "z-ai/glm-5.2", "zai-org/glm-5.2"},
		{"streamlake", "kwaipilot/kat-coder-pro-v2.5", "kat-coder-pro-v2.5"},
		{"neurometric", "ibm-granite/granite-4.1-8b", "ibm-granite/granite-4.1-8b"},
		{"pearl", "deepseek/deepseek-v4-pro", "deepseek-ai/DeepSeek-V4-Pro"},
		{"engy", "z-ai/glm-5.2", "glm-5.2"},
		{"databricks", "z-ai/glm-5.2", "databricks-glm-5-2"},
		{"zero-g", "z-ai/glm-5.2", "glm-5.2"},
		{"alibaba", "qwen/qwen3.7-flash", "qwen3.7-flash"},
	}
	for _, tc := range cases {
		if got := directModelID(tc.provider, tc.model, tc.upstream); got != tc.upstream {
			t.Errorf("directModelID(%q) = %q, want %q", tc.provider, got, tc.upstream)
		}
	}
}

func TestDatabricksServingBaseURL(t *testing.T) {
	t.Parallel()

	valid := map[string]string{
		"dbc-1234.cloud.databricks.com":          "https://dbc-1234.cloud.databricks.com/serving-endpoints",
		"https://adb-123.azuredatabricks.net/":   "https://adb-123.azuredatabricks.net/serving-endpoints",
		"https://dbc-123.gcp.databricks.com:443": "https://dbc-123.gcp.databricks.com/serving-endpoints",
	}
	for raw, want := range valid {
		got, err := databricksServingBaseURL(raw)
		if err != nil {
			t.Errorf("databricksServingBaseURL(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("databricksServingBaseURL(%q) = %q, want %q", raw, got, want)
		}
	}

	invalid := []string{
		"",
		"http://dbc-1234.cloud.databricks.com",
		"https://dbc-1234.cloud.databricks.com:8443",
		"https://user@dbc-1234.cloud.databricks.com",
		"https://dbc-1234.cloud.databricks.com/path",
		"https://dbc-1234.cloud.databricks.com?next=evil",
		"https://cloud.databricks.com.evil.example",
		"https://127.0.0.1",
	}
	for _, raw := range invalid {
		if got, err := databricksServingBaseURL(raw); err == nil {
			t.Errorf("databricksServingBaseURL(%q) = %q, want rejection", raw, got)
		}
	}
}
