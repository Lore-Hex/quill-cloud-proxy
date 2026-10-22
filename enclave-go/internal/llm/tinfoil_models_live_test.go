package llm

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestLiveTinfoilDecisions(t *testing.T) {
	if os.Getenv("TR_LIVE_TINFOIL_DECISIONS") != "1" {
		t.Skip("set TR_LIVE_TINFOIL_DECISIONS=1 and run the real attest-sidecar")
	}
	key := strings.TrimSpace(os.Getenv("TINFOIL_API_KEY"))
	if key == "" {
		t.Fatal("TINFOIL_API_KEY required")
	}
	client := newTinfoilAttested(key)
	for _, size := range []string{"small", "medium", "large"} {
		t.Run(size, func(t *testing.T) {
			req, specs := hostedRequest(t)
			req.Model = "tinfoil/decision-" + size
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			started := time.Now()
			response, err := client.InvokeDecide(ctx, req, InvokeOptions{
				Provider: "tinfoil", UpstreamModel: "decision-" + size,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decide.Verify(specs, response.Answers); err != nil {
				t.Fatal(err)
			}
			if response.InputTokens <= 0 || response.OutputTokens != 0 {
				t.Fatal("invalid billable usage")
			}
			t.Logf("verified transport: input_tokens=%d output_tokens=0 latency=%s", response.InputTokens, time.Since(started))
		})
	}
}

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
