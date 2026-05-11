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
