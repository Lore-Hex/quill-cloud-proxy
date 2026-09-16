//go:build live_provider_wave && llm_multi

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

func TestLiveOpenRouterCatalogDispatch(t *testing.T) {
	if os.Getenv("TR_LIVE_OPENROUTER") != "1" {
		t.Skip("set TR_LIVE_OPENROUTER=1 and OPENROUTER_API_KEY for the synthetic live probe")
	}
	key := strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY"))
	if key == "" {
		t.Fatal("OPENROUTER_API_KEY is required")
	}
	const model = "stealth/union-alpha"
	maxTokens := 64
	client := New(&qtypes.BootstrapData{OpenRouterAPIKey: key})
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	var out bytes.Buffer
	err := client.InvokeStreaming(ctx,
		&qtypes.OpenAIChatRequest{Model: model, MaxTokens: &maxTokens},
		&qtypes.AnthropicMessagesRequest{MaxTokens: maxTokens,
			Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Reply exactly PONG."}}},
		&out, InvokeOptions{Provider: "openrouter", UpstreamModel: model, UsageType: "Credits"})
	if err != nil {
		t.Fatal(err)
	}
	visible, err := providerWaveVisibleText(out.Bytes())
	if err != nil || !strings.Contains(strings.ToUpper(visible), "PONG") {
		t.Fatalf("expected PONG: stream_bytes=%d parse_error=%v", out.Len(), err)
	}
	input, output := 0, 0
	for _, line := range strings.Split(out.String(), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var event struct {
			Message struct {
				Usage map[string]int `json:"usage"`
			} `json:"message"`
			Usage map[string]int `json:"usage"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) == nil {
			input = max(input, event.Message.Usage["input_tokens"], event.Usage["input_tokens"])
			output = max(output, event.Usage["output_tokens"])
		}
	}
	if input <= 0 || output <= 0 {
		t.Fatalf("missing billable usage: input=%d output=%d", input, output)
	}
	t.Logf("catalog dispatch returned PONG with input=%d output=%d", input, output)
}
