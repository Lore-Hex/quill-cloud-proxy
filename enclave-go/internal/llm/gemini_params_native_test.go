//go:build llm_multi

package llm

import (
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestNativeGeminiPayloadDropsSamplingFrom36(t *testing.T) {
	temperature, topP, topK := 0.2, 0.9, 40
	for model, want := range map[string]bool{"gemini-3.8-flash": false, "gemini-3.6-flash": false, "gemini-3.5-flash": true, "gemini-2.5-pro": true} {
		req := &qtypes.OpenAIChatRequest{Temperature: &temperature, TopP: &topP}
		body := &qtypes.AnthropicMessagesRequest{TopK: &topK}
		payload, err := vertexGeminiPayload(t.Context(), req, body, model)
		if err != nil {
			t.Fatal(err)
		}
		config, _ := payload["generationConfig"].(map[string]any)
		for _, key := range []string{"temperature", "topP", "topK"} {
			if _, got := config[key]; got != want {
				t.Fatalf("%s: %s present=%v, want %v", model, key, got, want)
			}
		}
	}
}
