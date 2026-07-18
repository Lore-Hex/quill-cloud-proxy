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

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type byokRoundTripFunc func(*http.Request) (*http.Response, error)

func (f byokRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestOpenAICompatibleBYOKProvidersIncludeTogether(t *testing.T) {
	for _, provider := range []string{
		"openai",
		"cerebras",
		"deepseek",
		"mistral",
		"kimi",
		"gemini",
		"google-ai-studio",
		"zai",
		"together",
		"fireworks",
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
		"friendli",
		"baseten",
		"thinkingmachines",
		"wafer",
		"crusoe",
		"makora",
		"nebius",
		"minimax",
		"xiaomi",
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
	if isOpenAICompatibleBYOKProvider("google-vertex") {
		t.Fatal("Vertex must use workload identity, not an AI Studio BYOK key")
	}
}

func TestBuildOpenAICompatibleRequestCarriesInboundParams(t *testing.T) {
	seed := 7
	frequencyPenalty := 0.4
	presencePenalty := 0.8
	topK := 32
	n := 3
	logprobs := true
	topLogprobs := 2
	thinking := map[string]any{"type": "enabled", "budget_tokens": 1024}
	req := &qtypes.OpenAIChatRequest{
		Seed:             &seed,
		FrequencyPenalty: &frequencyPenalty,
		PresencePenalty:  &presencePenalty,
		N:                &n,
		LogitBias:        map[string]float64{"42": -1.5},
		Logprobs:         &logprobs,
		TopLogprobs:      &topLogprobs,
		Stop:             []string{"END"},
	}
	body := &qtypes.AnthropicMessagesRequest{
		MaxTokens:         123,
		MaxTokensExplicit: true,
		TopK:              &topK,
		Thinking:          thinking,
	}
	got := buildOpenAICompatibleRequest(
		"openai",
		"gpt-4o-mini",
		req,
		body,
		[]chatMessage{{Role: "user", Content: "hi"}},
	)
	if got.Seed == nil || *got.Seed != seed {
		t.Fatalf("seed = %#v, want %d", got.Seed, seed)
	}
	if got.FrequencyPenalty == nil || *got.FrequencyPenalty != frequencyPenalty {
		t.Fatalf("frequency_penalty = %#v", got.FrequencyPenalty)
	}
	if got.PresencePenalty == nil || *got.PresencePenalty != presencePenalty {
		t.Fatalf("presence_penalty = %#v", got.PresencePenalty)
	}
	if got.TopK == nil || *got.TopK != topK {
		t.Fatalf("top_k = %#v, want %d", got.TopK, topK)
	}
	if got.Thinking == nil {
		t.Fatal("thinking was not forwarded")
	}
	if got.LogitBias["42"] != -1.5 {
		t.Fatalf("logit_bias = %#v", got.LogitBias)
	}
	stop, ok := got.Stop.([]string)
	if !ok || len(stop) != 1 || stop[0] != "END" {
		t.Fatalf("stop = %#v", got.Stop)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	for _, key := range []string{"n", "logprobs", "top_logprobs"} {
		if _, ok := payload[key]; ok {
			t.Fatalf("%s present in payload: %s", key, encoded)
		}
	}
}

func TestBuildMetaOpenRouterRequestCarriesReasoningWithoutThinkingAlias(t *testing.T) {
	reasoning := map[string]any{"effort": "minimal"}
	req := &qtypes.OpenAIChatRequest{
		Reasoning:       reasoning,
		ReasoningEffort: "minimal",
	}
	body := &qtypes.AnthropicMessagesRequest{
		Thinking: map[string]any{"type": "enabled", "budget_tokens": 128},
	}

	got := buildOpenAICompatibleRequest(
		"meta",
		"meta/muse-spark-1.1",
		req,
		body,
		[]chatMessage{{Role: "user", Content: "Reply PONG"}},
	)
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["reasoning_effort"] != "minimal" {
		t.Fatalf("reasoning_effort = %#v, want minimal", payload["reasoning_effort"])
	}
	gotReasoning, ok := payload["reasoning"].(map[string]any)
	if !ok || gotReasoning["effort"] != "minimal" {
		t.Fatalf("reasoning = %#v, want minimal effort", payload["reasoning"])
	}
	if _, ok := payload["thinking"]; ok {
		t.Fatalf("Meta via OpenRouter must receive reasoning, not thinking: %s", encoded)
	}
	if got := directBaseURL("meta"); got != "https://openrouter.ai/api/v1" {
		t.Fatalf("directBaseURL(meta) = %q", got)
	}
	if got := directModelID("meta", "meta/muse-spark-1.1", "meta/muse-spark-1.1"); got != "meta/muse-spark-1.1" {
		t.Fatalf("directModelID(meta) = %q", got)
	}
}

func TestInvokeMetaUsesOpenRouterInferenceKeyAndExactMuseID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/chat/completions" {
			t.Errorf("path = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk-or-test" {
			t.Errorf("authorization = %q", got)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if payload["model"] != "meta/muse-spark-1.1" {
			t.Errorf("model = %#v", payload["model"])
		}
		if payload["reasoning_effort"] != "minimal" {
			t.Errorf("reasoning_effort = %#v", payload["reasoning_effort"])
		}
		if _, ok := payload["thinking"]; ok {
			t.Errorf("unexpected thinking alias in request: %#v", payload)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"PONG\"},\"finish_reason\":\"stop\"}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":1}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	req := &qtypes.OpenAIChatRequest{
		Model:           "meta/muse-spark-1.1",
		ReasoningEffort: "minimal",
	}
	body := &qtypes.AnthropicMessagesRequest{
		Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Reply PONG"}},
	}
	var out bytes.Buffer
	err := invokeOpenAICompatibleStreamingWithClient(
		context.Background(),
		server.Client(),
		"meta",
		server.URL,
		"sk-or-test",
		req,
		body,
		&out,
		"meta/muse-spark-1.1",
	)
	if err != nil {
		t.Fatalf("invoke Muse: %v", err)
	}
	if !strings.Contains(out.String(), `"text":"PONG"`) {
		t.Fatalf("translated output lost PONG: %s", out.String())
	}
}

func TestBuildOpenAICompatibleRequestOmitsRouterOnlyMetadata(t *testing.T) {
	req := &qtypes.OpenAIChatRequest{
		User:          "user-123",
		SessionID:     "matter-456",
		Trace:         map[string]any{"source": "eval"},
		Tags:          qtypes.NewRequestTags(qtypes.TagMap{"team": "legal"}),
		App:           "Contract Review",
		HTTPReferer:   "https://legal.example/app",
		AppCategories: []string{"legal"},
	}
	got := buildOpenAICompatibleRequest(
		"openai",
		"gpt-4o-mini",
		req,
		&qtypes.AnthropicMessagesRequest{},
		[]chatMessage{{Role: "user", Content: "private input"}},
	)
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, forbidden := range []string{
		"user-123",
		"matter-456",
		"source",
		"team",
		"Contract Review",
		"legal.example",
	} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("provider payload leaked %q: %s", forbidden, body)
		}
	}
}

func TestBuildOpenAICompatibleRequestOmitsAbsentInboundParams(t *testing.T) {
	got := buildOpenAICompatibleRequest(
		"openai",
		"gpt-4o-mini",
		&qtypes.OpenAIChatRequest{},
		&qtypes.AnthropicMessagesRequest{},
		nil,
	)
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	for _, key := range []string{
		"seed",
		"frequency_penalty",
		"presence_penalty",
		"logit_bias",
		"logprobs",
		"top_logprobs",
		"n",
		"stop",
		"top_k",
		"thinking",
	} {
		if _, ok := payload[key]; ok {
			t.Fatalf("%s present in payload: %s", key, encoded)
		}
	}
}

func TestBuildOpenAICompatibleRequestUsesSharedMaxTokensNotAnthropicThinkingBump(t *testing.T) {
	maxTokens := 100
	req := &qtypes.OpenAIChatRequest{
		Messages:        []qtypes.OpenAIChatMessage{{Role: "user", Content: "think"}},
		MaxTokens:       &maxTokens,
		ReasoningEffort: "high",
	}
	body, err := adapter.ToAnthropic(req, "model-ignored")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	if body.MaxTokens != maxTokens {
		t.Fatalf("shared MaxTokens = %d, want %d", body.MaxTokens, maxTokens)
	}
	if body.AnthropicDispatchMaxTokens() <= body.MaxTokens {
		t.Fatalf("AnthropicDispatchMaxTokens = %d, shared MaxTokens = %d", body.AnthropicDispatchMaxTokens(), body.MaxTokens)
	}
	got := buildOpenAICompatibleRequest(
		"openai",
		"gpt-4o-mini",
		req,
		body,
		[]chatMessage{{Role: "user", Content: "think"}},
	)
	if got.MaxTokens != maxTokens {
		t.Fatalf("OpenAI-compatible max_tokens = %d, want %d", got.MaxTokens, maxTokens)
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
		{"tinfoil", "moonshotai/kimi-k2.7-code", "kimi-k2-7-code"},
		{"tinfoil", "z-ai/glm-5.2", "glm-5-2"},
		{"tinfoil", "google/gemma-4-31b-it", "gemma4-31b"},
		{"tinfoil", "meta-llama/llama-3.3-70b-instruct", "llama3-3-70b"},
		{"tinfoil", "openai/gpt-oss-120b", "gpt-oss-120b"},
		{"tinfoil", "nomic-ai/nomic-embed-text", "nomic-embed-text"},
		// together — newly backfilled
		{"together", "meta-llama/llama-3.1-70b-instruct", "meta-llama/Llama-3.1-70B-Instruct-Turbo"},
		{"together", "mistralai/mixtral-8x7b-instruct", "mistralai/Mixtral-8x7B-Instruct-v0.1"},
		{"together", "deepseek/deepseek-v3-ocr", "deepseek-ai/DeepSeek-V3-OCR"},
		{"together", "z-ai/glm-5.2", "zai-org/GLM-5.2"},
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
		{"novita", "moonshotai/kimi-k2.7-code", "moonshotai/kimi-k2.7-code"},
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
		{"parasail", "z-ai/glm-5.2", "parasail-glm-52"},
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
		{"phala", "z-ai/glm-5.2", "phala/glm-5.2"},
		{"phala", "deepseek/deepseek-v3.2", "phala/deepseek-v3.2"},
		{"phala", "moonshotai/kimi-k2.6", "phala/kimi-k2.6"},
		{"phala", "google/gemma-3-27b-it", "phala/gemma-3-27b-it"},
		{"venice", "z-ai/glm-5.2", "zai-org-glm-5-2"},
		{"friendli", "z-ai/glm-5.2", "zai-org/GLM-5.2"},
		{"friendli", "meta-llama/llama-3.3-70b-instruct", "meta-llama-3.3-70b-instruct"},
		{"friendli", "qwen/qwen3-235b-a22b-2507", "Qwen/Qwen3-235B-A22B-Instruct-2507"},
		{"baseten", "z-ai/glm-5.2", "zai-org/GLM-5.2"},
		{"baseten", "moonshotai/kimi-k2.7-code", "moonshotai/Kimi-K2.7-Code"},
		{"baseten", "deepseek/deepseek-v4-pro", "deepseek-ai/DeepSeek-V4-Pro"},
		{"baseten", "nvidia/nemotron-3-ultra-550b-a55b", "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B"},
		{"baseten", "thinkingmachines/inkling-1m", "thinkingmachines/inkling"},
		{"thinkingmachines", "thinkingmachines/inkling", "thinkingmachines/Inkling:peft:262144"},
		{"wafer", "z-ai/glm-5.2", "GLM-5.2"},
		{"wafer", "moonshotai/kimi-k2.7-code", "Kimi-K2.7-Code"},
		{"wafer", "minimax/minimax-m3", "MiniMax-M3"},
		{"crusoe", "z-ai/glm-5.2", "zai/GLM-5.2"},
		{"crusoe", "deepseek/deepseek-v4-flash", "deepseek-ai/Deepseek-V4-Flash"},
		{"crusoe", "moonshotai/kimi-k2.6", "moonshotai/Kimi-K2.6"},
		{"crusoe", "qwen/qwen3-235b-a22b-2507", "Qwen/Qwen3-235B-A22B-Instruct-2507"},
		{"makora", "deepseek/deepseek-v4-flash", "deepseek-ai/DeepSeek-V4-Flash"},
		{"makora", "deepseek/deepseek-v4-pro", "deepseek-ai/DeepSeek-V4-Pro"},
		{"makora", "google/gemma-4-26b-a4b-it", "google/gemma-4-26B-A4B"},
		{"makora", "z-ai/glm-5.2", "zai-org/GLM-5.2-FP8"},
		{"makora", "z-ai/glm-5.2-nvfp4", "zai-org/GLM-5.2-NVFP4"},
		{"makora", "moonshotai/kimi-k2.7-code", "moonshotai/Kimi-K2.7-Code"},
		{"makora", "qwen/qwen3.6-27b", "unsloth/Qwen3.6-27B-NVFP4"},
		{"makora", "qwen/qwen3.6-35b-a3b", "unsloth/Qwen3.6-35B-A3B-NVFP4"},
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
		{"siliconflow", "minimax/minimax-m3", "minimax/minimax-m3", "MiniMaxAI/MiniMax-M3"},
		{"siliconflow", "tencent/hunyuan-a13b-instruct", "tencent/hunyuan-a13b-instruct", "tencent/Hunyuan-A13B-Instruct"},
		{"siliconflow", "z-ai/glm-5", "z-ai/glm-5", "zai-org/GLM-5"},
		{"siliconflow", "z-ai/glm-5.2", "z-ai/glm-5.2", "zai-org/GLM-5.2"},
		{"siliconflow", "z-ai/glm-5v-turbo", "z-ai/glm-5v-turbo", "zai-org/GLM-5V-Turbo"},
		// DeepInfra keeps the upstream author path and mixed-case GLM
		// version. Without this provider-specific map, directModelID strips
		// the author and sends bare "GLM-5.2", which DeepInfra rejects.
		{"deepinfra", "z-ai/glm-5.2", "zai-org/GLM-5.2", "zai-org/GLM-5.2"},
		{"gmi", "z-ai/glm-5.2", "zai-org/GLM-5.2-FP8", "zai-org/GLM-5.2-FP8"},
		{"friendli", "z-ai/glm-5.2", "zai-org/GLM-5.2", "zai-org/GLM-5.2"},
		{"baseten", "z-ai/glm-5.2", "zai-org/GLM-5.2", "zai-org/GLM-5.2"},
		{"baseten", "nvidia/nemotron-3-ultra-550b-a55b", "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B", "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B"},
		{"baseten", "thinkingmachines/inkling-1m", "thinkingmachines/inkling", "thinkingmachines/inkling"},
		{"thinkingmachines", "thinkingmachines/inkling", "thinkingmachines/Inkling:peft:262144", "thinkingmachines/Inkling:peft:262144"},
		{"wafer", "z-ai/glm-5.2", "GLM-5.2", "GLM-5.2"},
		// zai-direct accepts only the bare id; glm-4.7 was mis-mapped to
		// "zai-glm-4.7" by the global directModelMap.
		{"zai", "z-ai/glm-4.7", "z-ai/glm-4.7", "glm-4.7"},
		{"zai", "z-ai/glm-5.2", "z-ai/glm-5.2", "glm-5.2"},
		// zai glm-4.5 has no override — must still strip-prefix to the bare
		// id (regression guard: adding zai to providerNativeModelMaps must
		// not break the models that already worked via strip-author).
		{"zai", "z-ai/glm-4.5", "z-ai/glm-4.5", "glm-4.5"},
		// mistral rejects bare "mistral-large" ("Invalid model"); directModelMap
		// remaps it to the "mistral-large-latest" alias.
		{"mistral", "mistralai/mistral-large", "mistralai/mistral-large", "mistral-large-latest"},
		{"mistral", "mistralai/mistral-small-3.2-24b-instruct", "mistralai/mistral-small-3.2-24b-instruct", "mistral-small-2506"},
		{"mistral", "mistralai/mistral-nemo", "mistralai/mistral-nemo", "open-mistral-nemo"},
		{"kimi", "moonshotai/kimi-k3", "kimi-k3", "kimi-k3"},
		{"kimi", "moonshotai/kimi-k2.7-code", "moonshotai/kimi-k2.7-code", "moonshotai/Kimi-K2.7-Code"},
		// anthropic path calls directModelID FIRST, so claude-4.0's dated-id
		// remap must resolve here (the bare "claude-opus-4" 404s on Anthropic).
		{"anthropic", "anthropic/claude-opus-4.8", "anthropic/claude-opus-4.8", "claude-opus-4-8"},
		{"anthropic", "anthropic/claude-haiku-4.5", "anthropic/claude-haiku-4.5", "claude-haiku-4-5-20251001"},
		{"anthropic", "anthropic/claude-sonnet-4.5", "anthropic/claude-sonnet-4.5", "claude-sonnet-4-5-20250929"},
		{"anthropic", "anthropic/claude-opus-4.5", "anthropic/claude-opus-4.5", "claude-opus-4-5-20251101"},
		{"anthropic", "anthropic/claude-opus-4.1", "anthropic/claude-opus-4.1", "claude-opus-4-1-20250805"},
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

func TestDirectModelIDStripsOpenRouterVariantBeforeMapping(t *testing.T) {
	base := directModelID("anthropic", "anthropic/claude-opus-4.7", "anthropic/claude-opus-4.7")
	if base != "claude-opus-4-7" {
		t.Fatalf("directModelID(base) = %q, want claude-opus-4-7", base)
	}
	for _, model := range []string{
		"anthropic/claude-opus-4.7:extended",
		"anthropic/claude-opus-4.7:floor",
		"anthropic/claude-opus-4.7:nitro",
		"anthropic/claude-opus-4.7:online",
	} {
		if got := directModelID("anthropic", model, model); got != base {
			t.Fatalf("directModelID(%q) = %q, want %q", model, got, base)
		}
	}
	if got := stripOpenRouterModelVariant("provider:namespace/model"); got != "provider:namespace/model" {
		t.Fatalf("stripOpenRouterModelVariant stripped unknown colon segment: %q", got)
	}
}

func TestFireworksDirectModelIDPreservesFullUpstreamResource(t *testing.T) {
	got := directModelID(
		"fireworks",
		"openai/gpt-oss-120b",
		"accounts/fireworks/models/gpt-oss-120b",
	)
	want := "accounts/fireworks/models/gpt-oss-120b"
	if got != want {
		t.Fatalf("directModelID(fireworks) = %q, want %q", got, want)
	}
}

func TestAnthropicBYOKOmitsTemperatureForSuffixedOpusVariant(t *testing.T) {
	temp := 0.5
	var payload map[string]any
	httpc := &http.Client{
		Transport: byokRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != "https://api.anthropic.com/v1/messages" {
				t.Fatalf("url = %q", req.URL.String())
			}
			if got := req.Header.Get("x-api-key"); got != "sk-test" {
				t.Fatalf("x-api-key = %q", got)
			}
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")),
			}, nil
		}),
	}
	err := invokeAnthropicBYOKStreamingWithClient(
		t.Context(),
		httpc,
		&qtypes.OpenAIChatRequest{Model: "anthropic/claude-opus-4.7:extended"},
		&qtypes.AnthropicMessagesRequest{
			Messages:    []qtypes.AnthropicMessage{{Role: "user", Content: "hi"}},
			MaxTokens:   8,
			Temperature: &temp,
		},
		io.Discard,
		"sk-test",
		"",
	)
	if err != nil {
		t.Fatalf("invokeAnthropicBYOKStreaming: %v", err)
	}
	if payload["model"] != "claude-opus-4-7" {
		t.Fatalf("model = %#v, want claude-opus-4-7; payload=%#v", payload["model"], payload)
	}
	if _, ok := payload["temperature"]; ok {
		t.Fatalf("opus temperature present: %#v", payload["temperature"])
	}
}

func TestProviderSpecificTemperatureOmission(t *testing.T) {
	zero := 0.0
	if got := openAICompatibleTemperature("kimi", "kimi-k2.6", &zero); got != nil {
		t.Fatalf("Kimi K2.6 temperature = %v, want omitted", *got)
	}
	if got := openAICompatibleTemperature("kimi", "kimi-k3", &zero); got != nil {
		t.Fatalf("Kimi K3 temperature = %v, want omitted", *got)
	}
	if got := openAICompatibleTemperature("openai", "gpt-4o-mini", &zero); got == nil || *got != 0 {
		t.Fatalf("OpenAI temperature = %v, want 0", got)
	}
	// gpt-5.x / o-series reject temperature != 1; must be omitted (this is what
	// 400'd the Fusion panel's gpt-5.5 panelist).
	for _, m := range []string{"gpt-5.5", "openai/gpt-5.5", "gpt-5.4-mini", "o3"} {
		if got := openAICompatibleTemperature("openai", m, &zero); got != nil {
			t.Fatalf("OpenAI %s temperature = %v, want omitted", m, *got)
		}
	}
	if got := anthropicTemperature("claude-opus-4-8", &zero); got != nil {
		t.Fatalf("Claude Opus 4.8 temperature = %v, want omitted", *got)
	}
	if got := anthropicTemperature("claude-opus-4-7", &zero); got != nil {
		t.Fatalf("Claude Opus 4.7 temperature = %v, want omitted", *got)
	}
	for _, model := range []string{
		"claude-fable-5",
		"anthropic/claude-fable-5",
		"claude-sonnet-5-20260901",
		"claude-haiku-5",
	} {
		if got := anthropicTemperature(model, &zero); got != nil {
			t.Fatalf("%s temperature = %v, want omitted", model, *got)
		}
	}
	if got := anthropicTemperature("claude-sonnet-4-6", &zero); got == nil || *got != 0 {
		t.Fatalf("Claude Sonnet temperature = %v, want 0", got)
	}
	hot := 1.7
	if got := anthropicTemperature("claude-sonnet-4-6", &hot); got == nil || *got != 1.0 {
		t.Fatalf("Claude Sonnet high temperature = %v, want 1.0", got)
	}
}

func TestClaude5GenerationRegexp(t *testing.T) {
	tests := []struct {
		model string
		want  bool
	}{
		{"claude-fable-5", true},
		{"anthropic/claude-fable-5", true},
		{"claude-sonnet-5-20260901", true},
		{"claude-haiku-5", true},
		{"claude-sonnet-4-6", false},
		{"claude-opus-4-8", false},
		{"claude-3-5-sonnet", false},
		{"claude-3-5-sonnet-20241022", false},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			if got := claude5Generation.MatchString(strings.ToLower(tt.model)); got != tt.want {
				t.Fatalf("claude5Generation.MatchString(%q) = %v, want %v", tt.model, got, tt.want)
			}
		})
	}
}

func TestWaferZDRHeaderContract(t *testing.T) {
	tests := []struct {
		name          string
		model         string
		upstreamModel string
		wantModel     string
		wantZDR       bool
	}{
		{
			name:          "glm remains zdr native",
			model:         "z-ai/glm-5.2",
			upstreamModel: "GLM-5.2",
			wantModel:     "GLM-5.2",
			wantZDR:       true,
		},
		{
			name:          "kimi k2.6 is standard tier",
			model:         "moonshotai/kimi-k2.6",
			upstreamModel: "Kimi-K2.6",
			wantModel:     "Kimi-K2.6",
			wantZDR:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpc := &http.Client{
				Transport: byokRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.String() != "https://pass.wafer.ai/v1/chat/completions" {
						t.Fatalf("url = %q", req.URL.String())
					}
					gotZDR := req.Header.Get("Wafer-ZDR")
					if tt.wantZDR && gotZDR != "required" {
						t.Fatalf("Wafer-ZDR header = %q, want required", gotZDR)
					}
					if !tt.wantZDR && gotZDR != "" {
						t.Fatalf("Wafer-ZDR header = %q, want omitted", gotZDR)
					}

					var payload map[string]any
					if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
						t.Fatalf("decode request body: %v", err)
					}
					if payload["model"] != tt.wantModel {
						t.Fatalf("model = %#v, want %q; payload=%#v", payload["model"], tt.wantModel, payload)
					}

					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
						Body: io.NopCloser(strings.NewReader(strings.Join([]string{
							`data: {"id":"x","choices":[{"delta":{"content":"ok"},"finish_reason":null}]}`,
							``,
							`data: {"id":"x","choices":[{"delta":{},"finish_reason":"stop"}]}`,
							``,
							`data: [DONE]`,
							``,
						}, "\n"))),
					}, nil
				}),
			}

			err := invokeOpenAICompatibleStreamingWithClient(
				t.Context(),
				httpc,
				"wafer",
				"https://pass.wafer.ai/v1",
				"sk-test",
				&qtypes.OpenAIChatRequest{Model: tt.model},
				&qtypes.AnthropicMessagesRequest{
					Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "hi"}},
					MaxTokens: 8,
				},
				io.Discard,
				tt.upstreamModel,
			)
			if err != nil {
				t.Fatalf("invokeOpenAICompatibleStreamingWithClient: %v", err)
			}
		})
	}
}
