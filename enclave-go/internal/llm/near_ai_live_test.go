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

// This smoke is intentionally opt-in: it verifies fresh Intel and NVIDIA
// evidence, proves that evidence binds the live TLS connection, and performs
// one direct NEAR AI inference. Run it with the real attest-sidecar listening
// on TINFOIL_ATTEST_SOCKET.
func TestLiveNearAIDirectAttestedPong(t *testing.T) {
	if os.Getenv("TR_LIVE_NEAR_AI") != "1" {
		t.Skip("set TR_LIVE_NEAR_AI=1 to run the live attested NEAR AI smoke")
	}
	apiKey := strings.TrimSpace(os.Getenv("NEAR_API_KEY"))
	if apiKey == "" {
		t.Fatal("NEAR_API_KEY is required")
	}
	model := strings.TrimSpace(os.Getenv("TR_LIVE_NEAR_AI_MODEL"))
	if model == "" {
		model = "z-ai/glm-5.2"
	}
	maxTokens := 8
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client := newNearAI(apiKey)
	var output bytes.Buffer
	err := client.InvokeStreaming(
		ctx,
		&qtypes.OpenAIChatRequest{Model: model, MaxTokens: &maxTokens},
		&qtypes.AnthropicMessagesRequest{
			Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "Reply with exactly PONG."}},
			MaxTokens: maxTokens,
		},
		&output,
		InvokeOptions{Provider: "near-ai", UpstreamModel: nearAIModelMap[model]},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(chutesLiveResponseText(output.Bytes())); !strings.EqualFold(got, "PONG") {
		t.Fatalf("live attested response = %q, want PONG; stream=%q", got, output.String())
	}
}
