package llm

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Opt-in, bounded paid probes using the real sidecar and pinned TLS transport.
func TestLiveTinfoilExpandedModels(t *testing.T) {
	if os.Getenv("TR_LIVE_TINFOIL_MODELS") != "1" {
		t.Skip("set TR_LIVE_TINFOIL_MODELS=1")
	}
	key := strings.TrimSpace(os.Getenv("TINFOIL_API_KEY"))
	if key == "" {
		t.Fatal("TINFOIL_API_KEY required")
	}
	client := newTinfoilAttested(key)
	for _, model := range []string{"llama3-3-70b", "gpt-oss-120b", "gpt-oss-safeguard-120b"} {
		t.Run(model, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			var output bytes.Buffer
			limit := 512
			err := client.InvokeStreaming(ctx, &qtypes.OpenAIChatRequest{Model: model, MaxTokens: &limit},
				&qtypes.AnthropicMessagesRequest{MaxTokens: limit, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Reply with the single word READY."}}},
				&output, InvokeOptions{Provider: "tinfoil", UpstreamModel: model})
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(chutesLiveResponseText(output.Bytes())) == "" {
				t.Fatal("no visible output")
			}
			if !bytes.Contains(output.Bytes(), []byte(`"input_tokens"`)) {
				t.Fatal("missing usage")
			}
		})
	}
	t.Run("nomic-embed-text", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		response, err := client.InvokeEmbedding(ctx, &qtypes.EmbeddingRequest{Model: "nomic-ai/nomic-embed-text", Input: "search_query: synthetic model availability check"}, InvokeOptions{Provider: "tinfoil", UpstreamModel: "nomic-embed-text"})
		if err != nil {
			t.Fatal(err)
		}
		if len(response.Data) != 1 || len(response.Data[0].Embedding) < 3 || response.Usage.PromptTokens <= 0 {
			t.Fatal("invalid embedding or missing usage")
		}
	})
}
