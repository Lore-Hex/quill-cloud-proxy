package directproviders

import "testing"

func TestLyceumDirectProvider(t *testing.T) {
	spec, ok := Lookup("lyceum")
	if !ok || spec.BaseURL != "https://api.lyceum.technology/openai/v1" || spec.ChatPath() != "/chat/completions" || spec.MediaOnly {
		t.Fatalf("incorrect Lyceum inference endpoint: %+v", spec)
	}
	if spec.SecretEnv != "QUILL_LYCEUM_SECRET" || spec.SecretName != "trustedrouter-lyceum-api-key" {
		t.Fatalf("incorrect Lyceum secret coordinates: %+v", spec)
	}
}
