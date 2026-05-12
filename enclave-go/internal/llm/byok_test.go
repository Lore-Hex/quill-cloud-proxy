package llm

import "testing"

func TestOpenAICompatibleBYOKProvidersIncludeTogether(t *testing.T) {
	for _, provider := range []string{
		"openai",
		"cerebras",
		"deepseek",
		"mistral",
		"kimi",
		"gemini",
		"zai",
		"together",
	} {
		if !isOpenAICompatibleBYOKProvider(provider) {
			t.Fatalf("%s should be an OpenAI-compatible BYOK provider", provider)
		}
		if directBaseURL(provider) == "" {
			t.Fatalf("%s is missing a direct base URL", provider)
		}
	}
	if isOpenAICompatibleBYOKProvider("anthropic") {
		t.Fatal("anthropic should use the native BYOK adapter")
	}
}

func TestTogetherDirectModelMapping(t *testing.T) {
	got := directModelID("together", "meta-llama/llama-3.3-70b-instruct", "")
	want := "meta-llama/Llama-3.3-70B-Instruct-Turbo"
	if got != want {
		t.Fatalf("directModelID for Together = %q, want %q", got, want)
	}
}

// TestGemma4DispatchMaps locks in the per-provider native-id mapping
// for the gemma-4 family. The bug this guards against is the one we
// hit live on 2026-05-11 where the generic `directModelID` fall-
// through stripped the `google/` author prefix and shipped a bare
// `gemma-4-31b-it` to providers that expected their own native
// slugs ⇒ HTTP 400 "failed to find the model" for ALL five new
// gemma-4 hosts.
func TestGemma4DispatchMaps(t *testing.T) {
	cases := []struct {
		provider string
		want     string
	}{
		{"lightning", "lightning-ai/gemma-4-31B-it"},
		{"parasail", "parasail-gemma-4-31b-it"},
		{"deepinfra", "google/gemma-4-31B-it"},
		{"gmi", "google/gemma-4-31b-it"},
	}
	for _, tc := range cases {
		got := directModelID(tc.provider, "google/gemma-4-31b-it", "google/gemma-4-31b-it")
		if got != tc.want {
			t.Errorf("directModelID(%q, google/gemma-4-31b-it) = %q, want %q", tc.provider, got, tc.want)
		}
	}
}

// TestPerProviderNativeMaps covers the broader audit — every entry
// in `providerNativeModelMaps` should resolve to its mapped native
// id when dispatched against that provider. The non-gemma-4
// regressions caught during the 2026-05-11 audit (tinfoil's
// `kimi-k2-6`, together's backfilled `Llama-3.1-70B-Instruct-Turbo`,
// deepinfra's `Meta-Llama-3.1-70B-Instruct`, etc.) all live here
// so future strip-author refactors fail loudly.
func TestPerProviderNativeMaps(t *testing.T) {
	cases := []struct {
		provider, orID, want string
	}{
		// tinfoil — every model has a dot→dash or strip-author transform
		{"tinfoil", "moonshotai/kimi-k2.6", "kimi-k2-6"},
		{"tinfoil", "z-ai/glm-5.1", "glm-5-1"},
		{"tinfoil", "meta-llama/llama-3.3-70b-instruct", "llama3-3-70b"},
		{"tinfoil", "openai/gpt-oss-120b", "gpt-oss-120b"},
		{"tinfoil", "nomic-ai/nomic-embed-text", "nomic-embed-text"},
		// together — newly backfilled
		{"together", "meta-llama/llama-3.1-70b-instruct", "meta-llama/Llama-3.1-70B-Instruct-Turbo"},
		{"together", "mistralai/mixtral-8x7b-instruct", "mistralai/Mixtral-8x7B-Instruct-v0.1"},
		{"together", "deepseek/deepseek-v3-ocr", "deepseek-ai/DeepSeek-V3-OCR"},
		// lightning — non-gemma
		{"lightning", "meta-llama/llama-3.3-70b-instruct", "lightning-ai/llama-3.3-70b"},
		{"lightning", "deepseek/deepseek-v3.1", "lightning-ai/DeepSeek-V3.1"},
		// parasail — non-gemma
		{"parasail", "meta-llama/llama-3.3-70b-instruct", "parasail-llama-33-70b-fp8"},
		{"parasail", "qwen/qwen2.5-vl-72b-instruct", "parasail-qwen25-vl-72b-instruct"},
		// deepinfra — non-gemma
		{"deepinfra", "meta-llama/llama-3.3-70b-instruct", "meta-llama/Llama-3.3-70B-Instruct"},
		{"deepinfra", "deepseek/deepseek-v3.1", "deepseek-ai/DeepSeek-V3.1"},
		{"deepinfra", "qwen/qwen3.5-27b", "Qwen/Qwen3.5-27B"},
		// gmi — non-gemma
		{"gmi", "deepseek/deepseek-v4-pro", "deepseek-ai/DeepSeek-V4-Pro"},
		{"gmi", "z-ai/glm-5.1", "zai-org/GLM-5.1-FP8"},
		{"gmi", "openai/gpt-5.5", "openai/gpt-5.5"},
		// novita — confirmed via live 2026-05-11 audit (no scraper
		// map, but strip-author still 404s on gemma-4)
		{"novita", "google/gemma-4-31b-it", "google/gemma-4-31b-it"},
		{"novita", "google/gemma-4-26b-a4b-it", "google/gemma-4-26b-a4b-it"},
		// parasail — 2026-05-12 expansion to 31 models; sample
		// covers each native-id pattern: parasail-* slug, mixed-
		// case proprietary author paths, dot-versioned models.
		{"parasail", "deepseek/deepseek-v4-pro", "parasail-deepseek-v4-pro"},
		{"parasail", "z-ai/glm-5.1", "parasail-glm-51"},
		{"parasail", "moonshotai/kimi-k2.6", "parasail-kimi-k26"},
		{"parasail", "openai/gpt-oss-120b", "parasail-gpt-oss-120b"},
		{"parasail", "thedrummer/cydonia-24b-v4.1", "parasail-cydonia-24-v41"},
		{"parasail", "arcee-ai/trinity-large-thinking", "parasail-trinity-large-thinking"},
		{"parasail", "bytedance/ui-tars-1.5-7b", "parasail-ui-tars-1p5-7b"},
		{"parasail", "qwen/qwen3-next-80b-a3b-instruct", "parasail-qwen-3-next-80b-instruct"},
		// phala — 2026-05-12 revive after key rotation. Pattern
		// is prefix retention: send `openai/gpt-5.5` (not bare
		// `gpt-5.5`) to Phala's API since their /v1/models lists
		// the full author path.
		{"phala", "openai/gpt-5.5", "openai/gpt-5.5"},
		{"phala", "anthropic/claude-haiku-4.5", "anthropic/claude-haiku-4.5"},
		{"phala", "z-ai/glm-5", "z-ai/glm-5"},
		{"phala", "deepseek/deepseek-v3.2", "deepseek/deepseek-v3.2"},
	}
	for _, tc := range cases {
		got := directModelID(tc.provider, tc.orID, tc.orID)
		if got != tc.want {
			t.Errorf("directModelID(%q, %q) = %q, want %q", tc.provider, tc.orID, got, tc.want)
		}
	}
}
