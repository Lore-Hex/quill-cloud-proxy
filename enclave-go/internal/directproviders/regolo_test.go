package directproviders

import "testing"

func TestRegoloDirectEndpoint(t *testing.T) {
	spec, ok := Lookup("regolo")
	if !ok || spec.BaseURL != "https://api.regolo.ai/v1" || spec.ChatPath() != "/chat/completions" {
		t.Fatalf("Regolo direct endpoint = %#v, registered=%v", spec, ok)
	}
	if spec.SecretEnv != "QUILL_REGOLO_SECRET" || spec.SecretName != "trustedrouter-regolo-api-key" {
		t.Fatalf("incorrect Regolo secret coordinates: %#v", spec)
	}
}
