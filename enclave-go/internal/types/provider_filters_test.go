package types

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

func TestProviderFilterAliasesMatchRouter(t *testing.T) {
	// Generated from router routing.py, not a second hand-maintained alias table.
	// Regenerate/check with tools/sync_provider_alias_contract.py (see rollout doc).
	raw, err := os.ReadFile("testdata/provider_aliases.json")
	if err != nil {
		t.Fatal(err)
	}
	var aliases map[string][]string
	if err := json.Unmarshal(raw, &aliases); err != nil {
		t.Fatal(err)
	}
	for alias, want := range aliases {
		if got := NormalizeProviderFilters([]string{alias}); !slices.Equal(got, want) {
			t.Errorf("router alias %q: got %v, want %v", alias, got, want)
		}
	}
	for _, tc := range []struct {
		input string
		want  []string
	}{
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
