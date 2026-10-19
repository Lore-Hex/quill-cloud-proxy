package directproviders

import "testing"

func TestBedrockRegionalDirectProvider(t *testing.T) {
	spec, ok := Lookup("amazon-bedrock")
	if !ok || spec.BaseURL != "https://bedrock-mantle.us-east-1.api.aws/v1" || spec.ChatPath() != "/chat/completions" || spec.MediaOnly {
		t.Fatalf("incorrect Bedrock endpoint: %+v", spec)
	}
	if spec.SecretEnv != "QUILL_BEDROCK_SECRET" || spec.SecretName != "trustedrouter-bedrock-api-key" {
		t.Fatalf("incorrect Bedrock secret coordinates: %+v", spec)
	}
}
