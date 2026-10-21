//go:build live_provider_wave

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestLiveRegoloDecision(t *testing.T) {
	key := os.Getenv("REGOLO_API_KEY")
	if key == "" || os.Getenv("TR_LIVE_REGOLO_DECIDE") != "1" {
		t.Skip("set REGOLO_API_KEY and TR_LIVE_REGOLO_DECIDE=1 for paid smoke")
	}
	client := &openAICompatibleClient{provider: "regolo", baseURL: directBaseURL("regolo"), apiKey: key, httpc: &http.Client{Timeout: 30 * time.Second}}
	runLiveRegoloDecision(t, client, InvokeOptions{Provider: "regolo", UpstreamModel: "clef-flash"})
}

func runLiveRegoloDecision(t *testing.T, client DecideClient, option InvokeOptions) {
	t.Helper()
	req := &DecideRequest{Model: "cloudflare/clef-flash", State: json.RawMessage(`"Mia owns a red bicycle."`), Questions: map[string]decide.Question{
		"red":   {Type: decide.TypeBoolean, Instructions: "Is the bicycle red?"},
		"color": {Type: decide.TypeChoice, Instructions: "What color is the bicycle?", Criteria: json.RawMessage(`{"red":null,"blue":null}`)},
		"score": {Type: decide.TypeScore, Instructions: "How red is the bicycle?", Criteria: json.RawMessage(`["Not red","Unclear","Clearly red"]`)},
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	response, err := client.InvokeDecide(ctx, req, option)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := decide.Parse(req.Questions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decide.Verify(specs, response.Answers); err != nil {
		t.Fatal(err)
	}
	if response.InputTokens <= 0 || response.OutputTokens != 0 || response.Answers["color"].Choice == nil || *response.Answers["color"].Choice != "red" {
		t.Fatal("unexpected decision or billing usage")
	}
	t.Logf("verified boolean, choice and score; input=%d output=%d", response.InputTokens, response.OutputTokens)
}

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
			inputTokens, outputTokens, reasoningTokens := 0, 0, 0
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
						InputTokens     int `json:"input_tokens"`
						OutputTokens    int `json:"output_tokens"`
						ReasoningTokens int `json:"reasoning_tokens"`
					} `json:"usage"`
				}
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) == nil {
					inputTokens = max(inputTokens, event.Message.Usage.InputTokens, event.Usage.InputTokens)
					outputTokens = max(outputTokens, event.Usage.OutputTokens)
					reasoningTokens = max(reasoningTokens, event.Usage.ReasoningTokens)
				}
			}
			if inputTokens <= 0 || outputTokens <= 0 {
				t.Fatalf("stream lacks positive billable usage: input=%d output=%d", inputTokens, outputTokens)
			}
			if reasoningTokens > 0 && outputTokens <= reasoningTokens {
				t.Fatalf("billable output omits visible or reasoning tokens: output=%d reasoning=%d", outputTokens, reasoningTokens)
			}
			t.Logf("PONG and usage received: input=%d output=%d reasoning=%d", inputTokens, outputTokens, reasoningTokens)
		})
	}
}
