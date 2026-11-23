package llm

import "testing"

func TestNitoRequiresExactOrdinaryChatVariant(t *testing.T) {
	for _, tc := range []struct{ model, native, want string }{
		{"org/model", "org/model:confidential", "org/model:confidential"},
		{"org/model", "", ""},
		{"org/model", "org/model", ""},
		{"org/model", "org/model:encrypted", ""},
		{"org/model:encrypted", "org/model:confidential", ""},
		{"org/model", "org/model:encrypted:confidential", ""},
	} {
		if got := directModelID("nito", tc.model, tc.native); got != tc.want {
			t.Fatalf("native %q resolved to %q", tc.native, got)
		}
	}
}
