package types

import "strings"

// NormalizeProviderFilters mirrors trusted_router/routing.py's _provider_slug
// and _provider_filter_list alias expansion. Unknown slugs remain for the
// control plane to validate against its catalog. Keep the pinned alias tests
// in sync when the router changes these tables; dispatch aliases are different.
func NormalizeProviderFilters(values []string) []string {
	aliases := map[string]string{
		"google-ai": "google-ai-studio", "ai-studio": "google-ai-studio",
		"google-vertex-ai": "google-vertex", "vertex": "google-vertex", "vertex-ai": "google-vertex",
		"chatgpt": "openai", "chat-gpt": "openai",
		"mistralai": "mistral", "mistral-ai": "mistral",
		"moonshot": "kimi", "moonshot-ai": "kimi", "kimi": "kimi",
		"z-ai": "zai", "zhipu": "zai", "zhipuai": "zai",
		"together-ai": "together", "togetherai": "together",
	}
	var out []string
	seen := make(map[string]bool)
	for _, value := range values {
		slug := strings.NewReplacer("_", "-", " ", "-").Replace(strings.ToLower(strings.TrimSpace(value)))
		slugs := []string{slug}
		if slug == "google" || slug == "gemini" {
			slugs = []string{"google-vertex", "google-ai-studio"}
		} else if alias, ok := aliases[slug]; ok {
			slugs = []string{alias}
		}
		for _, id := range slugs {
			if !seen[id] {
				out = append(out, id)
				seen[id] = true
			}
		}
	}
	return out
}
