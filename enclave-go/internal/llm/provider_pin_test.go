package llm

import (
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestFixedAdapterHonorsCallerProviderPins(t *testing.T) {
	req := &qtypes.OpenAIChatRequest{Provider: &qtypes.ProviderRouting{Only: []string{"vertex"}}}
	for _, tt := range []struct {
		fixed, chosen string
		allow         bool
	}{
		{"google-vertex", "google-vertex", true},
		{"google-vertex", "", true},
		{"anthropic", "google-vertex", false},
		{"google-vertex", "anthropic", false},
	} {
		err := rejectFixedProviderPrivate(t.Context(), req, tt.fixed, InvokeOptions{Provider: tt.chosen})
		if (err == nil) != tt.allow {
			t.Errorf("fixed %q, chosen %q: %v", tt.fixed, tt.chosen, err)
		}
	}
}
