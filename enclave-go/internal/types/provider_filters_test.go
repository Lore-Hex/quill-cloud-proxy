package types

import (
	"slices"
	"testing"
)

func TestProviderFilterAliasesMatchRouter(t *testing.T) {
	// Pin the complete routing.py _PROVIDER_ALIASES and
	// _PROVIDER_GROUP_ALIASES contract (not the LLM dispatch aliases).
	for _, tc := range []struct {
		input string
		want  []string
	}{
		{"google-ai", []string{"google-ai-studio"}},
		{"ai-studio", []string{"google-ai-studio"}},
		{"google-vertex-ai", []string{"google-vertex"}},
		{"vertex", []string{"google-vertex"}},
		{"vertex-ai", []string{"google-vertex"}},
		{"chatgpt", []string{"openai"}},
		{"chat-gpt", []string{"openai"}},
		{"mistralai", []string{"mistral"}},
		{"mistral-ai", []string{"mistral"}},
		{"moonshot", []string{"kimi"}},
		{"moonshot-ai", []string{"kimi"}},
		{"kimi", []string{"kimi"}},
		{"z-ai", []string{"zai"}},
		{"zhipu", []string{"zai"}},
		{"zhipuai", []string{"zai"}},
		{"together-ai", []string{"together"}},
		{"togetherai", []string{"together"}},
		{"gemini", []string{"google-vertex", "google-ai-studio"}},
		{"google", []string{"google-vertex", "google-ai-studio"}},
		{"  GOOGLE_AI Studio\t", []string{"google-ai-studio"}},
		{" Google  AI ", []string{"google--ai"}},
		{"BytePlus", []string{"byteplus"}},
		{"unknown_provider", []string{"unknown-provider"}},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := NormalizeProviderFilters([]string{tc.input}); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	if got := NormalizeProviderFilters([]string{"ai-studio", "google", "vertex", "gemini"}); !slices.Equal(got, []string{"google-ai-studio", "google-vertex"}) {
		t.Fatalf("lost order or deduplication: %v", got)
	}
}
