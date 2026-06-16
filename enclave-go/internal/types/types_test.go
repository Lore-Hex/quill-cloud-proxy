package types

import (
	"encoding/json"
	"testing"
)

func TestProviderRoutingAcceptsArrayAndCommaSeparatedString(t *testing.T) {
	var req OpenAIChatRequest
	if err := json.Unmarshal(
		[]byte(`{"model":"trustedrouter/zdr","messages":[],"provider":{"only":"google-vertex, anthropic","order":["openai","gemini"]}}`),
		&req,
	); err != nil {
		t.Fatalf("unmarshal chat request: %v", err)
	}
	if req.Provider == nil {
		t.Fatal("provider routing was nil")
	}
	if got, want := []string(req.Provider.Only), []string{"google-vertex", "anthropic"}; !equalStrings(got, want) {
		t.Fatalf("only = %#v, want %#v", got, want)
	}
	if got, want := []string(req.Provider.Order), []string{"openai", "gemini"}; !equalStrings(got, want) {
		t.Fatalf("order = %#v, want %#v", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
