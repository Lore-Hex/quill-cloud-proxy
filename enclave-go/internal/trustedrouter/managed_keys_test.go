package trustedrouter

import "testing"

func TestManagedCutoverScopedToMatchingPrepaidProvider(t *testing.T) {
	a := Authorization{ManagedKeyCutovers: map[string]string{"minimax": "first", "fal": "second", "other": "third"}}
	for _, tc := range []struct{ provider, usage, want string }{
		{"fal", "Credits", "second"}, {"minimax", "Credits", "first"}, {"fal", "BYOK", ""},
		{"other", "Credits", ""}, {"minimax", "", ""}, {"fal", "trial", ""},
	} {
		if got := a.ManagedKeyGeneration(tc.provider, tc.usage); got != tc.want {
			t.Fatal("incorrect scope")
		}
	}
	if (&Authorization{}).ManagedKeyGeneration("fal", "Credits") != "" {
		t.Fatal("unstaged provider selected")
	}
}
