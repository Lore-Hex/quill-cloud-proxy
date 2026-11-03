package decide

import "testing"

func TestEveryModelAliasNamesAHostedModel(t *testing.T) {
	for alias, canonical := range ModelAliases {
		if !IsHostedModel(canonical) || IsHostedModel(alias) {
			t.Errorf("%s -> %s: an alias must name a hosted model and not be one", alias, canonical)
		}
		if CanonicalModel(alias) != canonical || CanonicalModel(canonical) != canonical {
			t.Errorf("CanonicalModel(%s) = %s", alias, CanonicalModel(alias))
		}
	}
	if CanonicalModel("openai/gpt-oss-20b") != "openai/gpt-oss-20b" {
		t.Error("a chat model must pass through unchanged")
	}
}
