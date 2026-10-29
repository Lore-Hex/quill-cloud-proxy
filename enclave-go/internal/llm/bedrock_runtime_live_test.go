//go:build llm_multi

package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Opt-in paid synthetic. Ordinary CI must never require account credentials.
func TestBedrockRuntimeLiveQualifiedProfiles(t *testing.T) {
	key := os.Getenv("TR_TEST_BEDROCK_RUNTIME_KEY")
	if key == "" {
		t.Skip("explicit paid-path qualification only")
	}
	client := newBedrockRuntime(key)
	for model, profile := range bedrockRuntimeModels {
		t.Run(model, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			var out bytes.Buffer
			err := client.InvokeStreaming(ctx,
				&qtypes.OpenAIChatRequest{Model: model},
				&qtypes.AnthropicMessagesRequest{MaxTokens: 32, Messages: []qtypes.AnthropicMessage{{Role: "user", Content: "Reply exactly PONG."}}},
				&out, InvokeOptions{UpstreamModel: profile},
			)
			if err != nil {
				t.Fatal(err)
			}
			if !bedrockLivePong(out.Bytes()) {
				t.Fatal("missing synthetic answer or authenticated terminal completion")
			}
		})
	}
}

func bedrockLivePong(stream []byte) bool {
	var answer strings.Builder
	var finish string
	stops := 0
	scanner := bufio.NewScanner(bytes.NewReader(stream))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var event struct {
			Type  string `json:"type"`
			Delta struct {
				Type       string `json:"type"`
				Text       string `json:"text"`
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) != nil {
			return false
		}
		if event.Type == "content_block_delta" && event.Delta.Type == "text_delta" {
			answer.WriteString(event.Delta.Text)
		}
		if event.Type == "message_delta" && event.Delta.StopReason != "" {
			finish = event.Delta.StopReason
		}
		if event.Type == "message_stop" {
			stops++
		}
	}
	return scanner.Err() == nil && strings.TrimSpace(answer.String()) == "PONG" && finish == "end_turn" && stops == 1
}

func TestBedrockRuntimeLiveProbeAssemblesChunks(t *testing.T) {
	stream := []byte("data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"P\"}}\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"ONG\"}}\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n" +
		"data: {\"type\":\"message_stop\"}\n")
	if !bedrockLivePong(stream) || bedrockLivePong(bytes.ReplaceAll(stream, []byte("end_turn"), []byte("max_tokens"))) {
		t.Fatal("probe must assemble deltas and require a complete answer")
	}
}
