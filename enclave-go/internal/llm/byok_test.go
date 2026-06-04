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
		"grok",
		"novita",
		"phala",
		"siliconflow",
		"tinfoil",
		"venice",
		"parasail",
		"lightning",
		"gmi",
		"deepinfra",
		"nebius",
		"minimax",
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
		{"novita", "moonshotai/kimi-k2.6", "moonshotai/kimi-k2.6"},
		{"novita", "deepseek/deepseek-v4-flash", "deepseek/deepseek-v4-flash"},
		{"novita", "qwen/qwen3.5-27b", "qwen/qwen3.5-27b"},
		{"novita", "Sao10K/L3-8B-Stheno-v3.2", "Sao10K/L3-8B-Stheno-v3.2"},
		{"nebius", "Qwen/Qwen3.5-397B-A17B", "Qwen/Qwen3.5-397B-A17B"},
		{"nebius", "deepseek-ai/DeepSeek-V4-Pro", "deepseek-ai/DeepSeek-V4-Pro"},
		{"minimax", "minimax/minimax-m2.7", "MiniMax-M2.7"},
		{"minimax", "minimax/minimax-m2.7-highspeed", "MiniMax-M2.7-highspeed"},
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
		// phala — 2026-05-13 fix after the 2026-05-12 re-enable
		// returned 401 on every chat. Phala's TEE confidential-AI
		// product uses `phala/<bare>` as the model id (per their
		// docs at docs.phala.com/phala-cloud/confidential-ai/...);
		// the upstream-author form (`openai/gpt-5.5`,
		// `anthropic/claude-haiku-4.5`) hits a non-TEE
		// pass-through tier the key isn't entitled to.
		{"phala", "openai/gpt-oss-120b", "phala/gpt-oss-120b"},
		{"phala", "z-ai/glm-5", "phala/glm-5"},
		{"phala", "deepseek/deepseek-v3.2", "phala/deepseek-v3.2"},
		{"phala", "moonshotai/kimi-k2.6", "phala/kimi-k2.6"},
		{"phala", "google/gemma-3-27b-it", "phala/gemma-3-27b-it"},
	}
	for _, tc := range cases {
		got := directModelID(tc.provider, tc.orID, tc.orID)
		if got != tc.want {
			t.Errorf("directModelID(%q, %q) = %q, want %q", tc.provider, tc.orID, got, tc.want)
		}
	}
}

// Regression for the 2026-06-04 Together outage: in production the control
// plane sends the OR-canonical id in `model` and the endpoint's
// provider-native catalog id in `upstreamModel`. For Together that catalog id
// is MIXED-CASE ("moonshotai/Kimi-K2.6"), which misses the lowercase
// togetherModelMap key and used to fall through to the author-strip fallback,
// shipping a bare "Kimi-K2.6" that Together rejects ("Unable to access model
// Kimi-K2.6"). directModelID must resolve via the canonical `model` key
// regardless of the upstreamModel casing. (TestPerProviderNativeMaps passes
// orID as BOTH args, so it never caught this.)
func TestDirectModelIDResolvesMixedCaseUpstreamID(t *testing.T) {
	cases := []struct {
		provider, model, upstream, want string
	}{
		// Together native ids verified against api.together.xyz/v1/models.
		{"together", "moonshotai/kimi-k2.6", "moonshotai/Kimi-K2.6", "moonshotai/Kimi-K2.6"},
		{"together", "qwen/qwen-2.5-72b-instruct", "Qwen/Qwen2.5-72B-Instruct-Turbo", "Qwen/Qwen2.5-72B-Instruct-Turbo"},
		{"together", "qwen/qwen-2.5-7b-instruct", "Qwen/Qwen2.5-7B-Instruct-Turbo", "Qwen/Qwen2.5-7B-Instruct-Turbo"},
		// SiliconFlow native ids verified against api.siliconflow.com/v1/models
		// (mixed-case, different author prefix — deepseek-ai/*, zai-org/*).
		{"siliconflow", "deepseek/deepseek-v4-flash", "deepseek/deepseek-v4-flash", "deepseek-ai/DeepSeek-V4-Flash"},
		{"siliconflow", "deepseek/deepseek-v4-pro", "deepseek/deepseek-v4-pro", "deepseek-ai/DeepSeek-V4-Pro"},
		{"siliconflow", "tencent/hunyuan-a13b-instruct", "tencent/hunyuan-a13b-instruct", "tencent/Hunyuan-A13B-Instruct"},
		{"siliconflow", "z-ai/glm-5", "z-ai/glm-5", "zai-org/GLM-5"},
		// zai-direct accepts only the bare id; glm-4.7 was mis-mapped to
		// "zai-glm-4.7" by the global directModelMap.
		{"zai", "z-ai/glm-4.7", "z-ai/glm-4.7", "glm-4.7"},
		// zai glm-4.5 has no override — must still strip-prefix to the bare
		// id (regression guard: adding zai to providerNativeModelMaps must
		// not break the models that already worked via strip-author).
		{"zai", "z-ai/glm-4.5", "z-ai/glm-4.5", "glm-4.5"},
		// mistral rejects bare "mistral-large" ("Invalid model"); directModelMap
		// remaps it to the "mistral-large-latest" alias.
		{"mistral", "mistralai/mistral-large", "mistralai/mistral-large", "mistral-large-latest"},
		// anthropic path calls directModelID FIRST, so claude-4.0's dated-id
		// remap must resolve here (the bare "claude-opus-4" 404s on Anthropic).
		{"anthropic", "anthropic/claude-opus-4", "anthropic/claude-opus-4", "claude-opus-4-20250514"},
		{"anthropic", "anthropic/claude-sonnet-4", "anthropic/claude-sonnet-4", "claude-sonnet-4-20250514"},
	}
	for _, tc := range cases {
		got := directModelID(tc.provider, tc.model, tc.upstream)
		if got != tc.want {
			t.Errorf("directModelID(%q, %q, %q) = %q, want %q", tc.provider, tc.model, tc.upstream, got, tc.want)
		}
	}
}
