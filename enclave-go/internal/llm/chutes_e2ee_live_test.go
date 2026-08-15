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

// This smoke is intentionally opt-in: it sends fresh attestation evidence to
// Intel and NVIDIA and performs one encrypted Chutes inference. Run it with the
// real attest-sidecar listening on TINFOIL_ATTEST_SOCKET.
func TestLiveChutesE2EEAttestedPong(t *testing.T) {
	if os.Getenv("TR_LIVE_CHUTES_E2E") != "1" {
		t.Skip("set TR_LIVE_CHUTES_E2E=1 to run the live attested Chutes smoke")
	}
	apiKey := strings.TrimSpace(os.Getenv("CHUTES_API_KEY"))
	if apiKey == "" {
		t.Fatal("CHUTES_API_KEY is required")
	}
	model := strings.TrimSpace(os.Getenv("TR_LIVE_CHUTES_MODEL"))
	if model == "" {
		model = "moonshotai/Kimi-K2.6-TEE"
	}
	maxTokens := 8
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client := newChutesE2EE(apiKey)
	var output bytes.Buffer
	err := client.InvokeStreaming(
		ctx,
		&qtypes.OpenAIChatRequest{Model: model, MaxTokens: &maxTokens},
		&qtypes.AnthropicMessagesRequest{
			Messages:  []qtypes.AnthropicMessage{{Role: "user", Content: "Reply with exactly PONG."}},
			MaxTokens: maxTokens,
		},
		&output,
		InvokeOptions{Provider: "chutes", UpstreamModel: model},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(chutesLiveResponseText(output.Bytes())); !strings.EqualFold(got, "PONG") {
		t.Fatal("live encrypted response did not return the expected text")
	}
}

func chutesLiveResponseText(stream []byte) string {
	var text strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(stream))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var event struct {
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &event) == nil {
			text.WriteString(event.Delta.Text)
		}
	}
	return text.String()
}
