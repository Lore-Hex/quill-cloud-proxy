package llm

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/directproviders"
)

func TestRedpillIsNotPhala(t *testing.T) {
	for _, input := range []string{"redpill", "red-pill", "RedPill"} {
		if got := normalizeDirectProvider(input); got != "redpill" {
			t.Errorf("normalizeDirectProvider(%q) = %q, want redpill", input, got)
		}
	}
	if got := normalizeDirectProvider("phala"); got != "phala" {
		t.Fatalf("Phala identity changed: %q", got)
	}
	spec, ok := directproviders.Lookup("redpill")
	if !ok || spec.SecretName != "trustedrouter-redpill-api-key" || spec.BaseURL != "https://api.redpill.ai/v1" {
		t.Fatalf("Redpill requires its own compiled endpoint and secret: %+v", spec)
	}
}
