package types

import "testing"

func TestCanonicalRouterModelID(t *testing.T) {
	for source, want := range map[string]string{
		"trustedrouter/auto":         "trustedrouter/auto",
		"trustedrouter/auto-routing": "trustedrouter/auto",
		"nyte/auto":                  "trustedrouter/auto",
		"nyte/auto-routing":          "trustedrouter/auto",
		"nyte/auto-routing:zdr":      "trustedrouter/auto:zdr",
		"nyte/socrates-2.0":          "trustedrouter/socrates-2.0",
		"nyte/user-example":          "trustedrouter/user-example",
		"nyte/missing":               "trustedrouter/missing",
		"openai/auto-routing":        "openai/auto-routing",
		"notnyte/auto":               "notnyte/auto",
	} {
		if got := CanonicalRouterModelID(source); got != want {
			t.Errorf("%q: got %q want %q", source, got, want)
		}
	}
	r := &OpenAIChatRequest{Model: "nyte/auto-routing", Models: []string{"nyte/auto", "nyte/auto-routing:zdr", "openai/gpt-6-sol"}}
	r.NormalizeRouterModelAliases()
	if r.Model != "trustedrouter/auto" || r.Models[0] != r.Model || r.Models[1] != "trustedrouter/auto:zdr" || r.Models[2] != "openai/gpt-6-sol" {
		t.Fatalf("bad fallback normalization: %v", r)
	}
}
