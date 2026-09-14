//go:build live_provider_wave

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestLiveRegoloStreaming(t *testing.T) {
	key := os.Getenv("REGOLO_API_KEY")
	models := strings.Fields(os.Getenv("TR_LIVE_REGOLO_MODELS"))
	if key == "" || len(models) == 0 {
		t.Skip("set REGOLO_API_KEY and TR_LIVE_REGOLO_MODELS for paid smoke")
	}
	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			maxTokens := 512
			req := &qtypes.OpenAIChatRequest{Model: model, MaxTokens: &maxTokens}
			body := &qtypes.AnthropicMessagesRequest{
				MaxTokens: maxTokens,
				Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "Reply with exactly PONG and nothing else."}},
			}
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			var out bytes.Buffer
			err := InvokeOpenAICompatibleStreaming(ctx, "regolo", directBaseURL("regolo"), key, req, body, &out, model)
			if err != nil {
				t.Fatalf("provider stream failed: %v", err)
			}
			visible, err := providerWaveVisibleText(out.Bytes())
			if err != nil || strings.TrimSpace(visible) != "PONG" {
				t.Fatalf("PONG mismatch: %d visible bytes, %d stream bytes, parse error=%v", len(visible), out.Len(), err)
			}
			inputTokens, outputTokens := 0, 0
			for _, line := range strings.Split(out.String(), "\n") {
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				var event struct {
					Message struct {
						Usage struct {
							InputTokens int `json:"input_tokens"`
						} `json:"usage"`
					} `json:"message"`
					Usage struct {
						InputTokens  int `json:"input_tokens"`
						OutputTokens int `json:"output_tokens"`
					} `json:"usage"`
				}
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) == nil {
					inputTokens = max(inputTokens, event.Message.Usage.InputTokens, event.Usage.InputTokens)
					outputTokens = max(outputTokens, event.Usage.OutputTokens)
				}
			}
			if inputTokens <= 0 || outputTokens <= 0 {
				t.Fatalf("stream lacks positive billable usage: input=%d output=%d", inputTokens, outputTokens)
			}
			t.Logf("PONG and usage received (%d stream bytes)", out.Len())
		})
	}
}
