package directproviders

import "testing"

func TestTencentTokenHubContract(t *testing.T) {
	spec, ok := Lookup("tencent")
	if !ok {
		t.Fatal("Tencent TokenHub is not registered")
	}
	if spec.BaseURL != "https://tokenhub-intl.tencentcloudmaas.com/v1" || spec.ChatPath() != "/chat/completions" || spec.MediaOnly {
		t.Fatalf("unexpected Tencent endpoint: %#v", spec)
	}
	if spec.SecretEnv != "QUILL_TENCENT_SECRET" || spec.SecretName != "trustedrouter-tencent-tokenhub-api-key" {
		t.Fatalf("unexpected Tencent secret coordinates: %#v", spec)
	}
}
