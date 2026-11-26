package orderedkey

import "testing"

func TestOnlyMatchingOrderedPairCanSelectStandby(t *testing.T) {
	for _, provider := range []string{"fal", "minimax"} {
		gen := Generation(provider, "top", "bottom")
		if len(gen) != 64 {
			t.Fatal("missing pair binding")
		}
		for _, tc := range []struct{ p, a, b, decision, want string }{
			{provider, "top", "bottom", "", ""},
			{provider, "top", "bottom", "primary:" + gen, "top"},
			{provider, "top", "", "", "top"},
			{provider, "top", "bottom", gen, "bottom"},
			{provider, "top", "", gen, ""},
			{provider, "bottom", "top", gen, ""},
			{provider, "top", "third", gen, ""},
			{provider, "top", "top", gen, ""},
			{provider, "top", "bottom", "unavailable", ""},
			{"other", "top", "bottom", gen, ""},
		} {
			got, err := Select(tc.p, tc.a, tc.b, tc.decision)
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatal("unsafe credential selection")
			}
		}
	}
	if Generation("fal", "a", "b") == Generation("minimax", "a", "b") {
		t.Fatal("binding can move between providers")
	}
}
