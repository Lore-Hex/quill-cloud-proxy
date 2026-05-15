//go:build live_minimax

package llm

import (
	"bytes"
	"context"
	"os"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestLiveMiniMaxOpenAICompatibleStreaming(t *testing.T) {
	apiKey := os.Getenv("MINIMAX_API_KEY")
	if apiKey == "" {
		t.Skip("MINIMAX_API_KEY is not set")
	}
	maxTokens := 64
	req := &qtypes.OpenAIChatRequest{
		Model:     "minimax/minimax-m2.7-highspeed",
		MaxTokens: &maxTokens,
	}
	body := &qtypes.AnthropicMessagesRequest{
		MaxTokens: maxTokens,
		Messages: []qtypes.AnthropicMessage{
			{Role: "user", Content: "Reply exactly PONG."},
		},
	}
	var out bytes.Buffer
	err := InvokeOpenAICompatibleStreaming(
		context.Background(),
		"minimax",
		directBaseURL("minimax"),
		apiKey,
		req,
		body,
		&out,
		"MiniMax-M2.7-highspeed",
	)
	if err != nil {
		t.Fatalf("InvokeOpenAICompatibleStreaming: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("expected streamed Anthropic SSE bytes")
	}
	t.Logf("streamed %d bytes: %.240q", out.Len(), out.String())
}
