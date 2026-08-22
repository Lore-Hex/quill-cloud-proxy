//go:build live_provider_wave

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

func TestLiveProviderWaveChatModels(t *testing.T) {
	if os.Getenv("TR_LIVE_PROVIDER_WAVE") != "1" {
		t.Skip("set TR_LIVE_PROVIDER_WAVE=1 to run paid provider-wave chat smokes")
	}
	tests := []struct {
		provider string
		key      string
		model    string
	}{
		{provider: "stepfun", key: os.Getenv("STEPFUN_API_KEY"), model: "step-3.5-flash"},
		{provider: "stepfun", key: os.Getenv("STEPFUN_API_KEY"), model: "step-3.5-flash-2603"},
		{provider: "stepfun", key: os.Getenv("STEPFUN_API_KEY"), model: "step-3.7-flash"},
		{provider: "relace", key: os.Getenv("RELACE_API_KEY"), model: "deepseek-ai/DeepSeek-V4-Flash-0731"},
		{provider: "relace", key: os.Getenv("RELACE_API_KEY"), model: "moonshotai/kimi-k3"},
	}
	for _, tt := range tests {
		t.Run(tt.provider+"/"+tt.model, func(t *testing.T) {
			if strings.TrimSpace(tt.key) == "" {
				t.Fatalf("%s API key is required", tt.provider)
			}
			maxTokens := 256
			req := &qtypes.OpenAIChatRequest{Model: tt.model, MaxTokens: &maxTokens}
			body := &qtypes.AnthropicMessagesRequest{
				MaxTokens: maxTokens,
				Messages: []qtypes.AnthropicMessage{
					{Role: "user", Content: "Reply exactly PONG."},
				},
			}
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			var out bytes.Buffer
			err := InvokeOpenAICompatibleStreaming(
				ctx, tt.provider, directBaseURL(tt.provider), tt.key,
				req, body, &out, tt.model,
			)
			if err != nil {
				t.Fatal(err)
			}
			visible, err := providerWaveVisibleText(out.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.ToUpper(visible), "PONG") {
				t.Fatalf("stream did not reconstruct PONG (%d bytes, %d visible bytes)", out.Len(), len(visible))
			}
			t.Logf("received %d streamed bytes", out.Len())
		})
	}
}

func providerWaveVisibleText(raw []byte) (string, error) {
	var visible strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		var event struct {
			Delta struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return "", err
		}
		if event.Delta.Type == "text_delta" {
			visible.WriteString(event.Delta.Text)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return visible.String(), nil
}
