//go:build llm_multi && live_neurometric

package llm

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Opt-in: two small paid requests, synthetic input, no credential lookup.
func TestLiveNeurometricDecisionMetadata(t *testing.T) {
	if os.Getenv("TR_LIVE_NEUROMETRIC") != "1" {
		t.Skip("set TR_LIVE_NEUROMETRIC=1 to authorize two paid decision requests")
	}
	key := strings.TrimSpace(os.Getenv("NEUROMETRIC_API_KEY"))
	if key == "" {
		t.Fatal("NEUROMETRIC_API_KEY is required")
	}
	for _, stream := range []bool{false, true} {
		maxTokens := 32
		req := &qtypes.OpenAIChatRequest{Model: "neurometric/structured-decisions", Stream: stream, MaxTokens: &maxTokens,
			Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: `{"state":"Customer was charged twice and needs a refund.","question":"Which team handles this ticket?","options":{"billing":"Charges, refunds, invoices","technical":"Bugs and outages","sales":"Plans and upgrades"}}`}}}
		body, err := adapter.ToAnthropic(req, req.Model)
		if err != nil {
			t.Fatal(err)
		}
		var native bytes.Buffer
		if err := InvokeOpenAICompatibleStreaming(t.Context(), "neurometric", "https://wharf.neurometric.ai/v1", key, req, body, &native, req.Model); err != nil {
			status, _ := HTTPStatusFromError(err)
			t.Fatalf("status=%d error_type=%T", status, err)
		}
		var result adapter.StreamResult
		var out bytes.Buffer
		if stream {
			result, err = adapter.TransformStreamCaptureWithOptions(&native, &out, "live_decision", req.Model, true)
		} else {
			result, err = adapter.CollectAnthropicTextStrict(&native)
			if err == nil && result.Usage != nil {
				err = adapter.WriteChatCompletionResponseWithProviderMetadata(&out, "live_decision", req.Model, result.Text, "", nil,
					result.Usage.InputTokens, result.Usage.OutputTokens, result.Usage, 123, result.FinishReason, nil, nil, result.Decision)
			}
		}
		if err != nil || result.Decision["answer"] != "billing" || result.Decision["confidence"] == nil || result.Decision["probabilities"] == nil || result.Usage == nil || result.Usage.InputTokens <= 0 || result.Usage.OutputTokens != 0 {
			t.Fatalf("stream=%t decision/usage round-trip failed error_type=%T", stream, err)
		}
		if !strings.Contains(out.String(), `"decision"`) || !strings.Contains(out.String(), `"probabilities"`) {
			t.Fatal("public response lost decision metadata")
		}
		var answer struct{ Answer string }
		if json.Unmarshal([]byte(result.Text), &answer) != nil || answer.Answer != "billing" {
			t.Fatal("incorrect synthetic classification")
		}
		t.Logf("stream=%t decision/confidence/probabilities present; input_tokens=%d output_tokens=%d", stream, result.Usage.InputTokens, result.Usage.OutputTokens)
	}
}
