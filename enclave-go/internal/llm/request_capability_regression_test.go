package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestNestedEffortReachesCompatibleChatWire(t *testing.T) {
	for _, provider := range []string{"tinfoil", "grok", "baseten", "crusoe"} {
		for _, stream := range []bool{false, true} {
			for _, effort := range []string{"none", "low", "high", "medium", "not-an-effort"} {
				for _, responses := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%t/%s/responses=%t", provider, stream, effort, responses), func(t *testing.T) {
						req := &qtypes.OpenAIChatRequest{Model: "fixture", Stream: stream, Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "hello"}}, Reasoning: map[string]any{"effort": effort}}
						if responses {
							var err error
							req, err = adapter.ResponsesToChat(&qtypes.OpenAIResponsesRequest{Model: "fixture", Stream: stream, Input: "hello", Reasoning: map[string]any{"effort": effort}})
							if err != nil {
								t.Fatal(err)
							}
						}
						body, err := adapter.ToAnthropic(req, req.Model)
						if err != nil {
							t.Fatal(err)
						}
						msgs, err := openAICompatibleMessagesWithFetchedImages(context.Background(), body)
						if err != nil {
							t.Fatal(err)
						}
						prepared, err := PrepareChatRequest(provider, req.Model, req, body, msgs, ChatPreparationOptions{})
						if err != nil {
							t.Fatal(err)
						}
						var wire map[string]any
						if err := json.Unmarshal(prepared.Bytes, &wire); err != nil {
							t.Fatal(err)
						}
						if wire["reasoning_effort"] != effort || wire["reasoning"] != nil || wire["thinking"] != nil {
							t.Fatalf("effort lost or contradictory controls: %s", prepared.Bytes)
						}
						if req.Reasoning.(map[string]any)["effort"] != effort {
							t.Fatal("mutated caller")
						}
					})
				}
			}
		}
	}
}

func TestResponsesVisionMatchesChatProviderWire(t *testing.T) {
	// Compare the complete adapter chain, not just ResponsesToChat's output.
	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString(testPNG(t))
	chat := &qtypes.OpenAIChatRequest{Model: "z-ai/glm-5.3", Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: []any{
		map[string]any{"type": "text", "text": "Read the image"},
		map[string]any{"type": "image_url", "image_url": map[string]any{"url": image, "detail": "auto"}},
	}}}}
	responses, err := adapter.ResponsesToChat(&qtypes.OpenAIResponsesRequest{Model: chat.Model, Input: []any{map[string]any{"role": "user", "content": []any{
		map[string]any{"type": "input_text", "text": "Read the image"},
		map[string]any{"type": "input_image", "image_url": image},
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	var wires [][]byte
	for _, req := range []*qtypes.OpenAIChatRequest{chat, responses} {
		body, err := adapter.ToAnthropic(req, req.Model)
		if err != nil {
			t.Fatal(err)
		}
		msgs, err := openAICompatibleMessagesWithFetchedImages(context.Background(), body)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := PrepareChatRequest("baseten", "zai-org/GLM-5.3", req, body, msgs, ChatPreparationOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(prepared.Bytes, []byte(`"image_url"`)) {
			t.Fatalf("image lost: %s", prepared.Bytes)
		}
		wires = append(wires, prepared.Bytes)
	}
	if !bytes.Equal(wires[0], wires[1]) {
		t.Fatalf("Chat/Responses differ:\n%s\n%s", wires[0], wires[1])
	}
}

func TestKimiK3EffortContract(t *testing.T) {
	for _, effort := range []string{"", "low", "high", "max", "medium", "none", "nonsense"} {
		for _, nested := range []bool{false, true} {
			req := &qtypes.OpenAIChatRequest{Model: "moonshotai/kimi-k3", ReasoningEffort: effort}
			if nested {
				req.ReasoningEffort = ""
				req.Reasoning = map[string]any{"effort": effort}
			}
			_, err := PrepareChatRequest("kimi", "kimi-k3", req, nil, nil, ChatPreparationOptions{})
			valid := effort == "" || effort == "low" || effort == "high" || effort == "max"
			if valid && err != nil {
				t.Fatalf("valid effort %q rejected: %v", effort, err)
			}
			var upstream *upstreamHTTPError
			if !valid && (!errors.As(err, &upstream) || upstream.status != http.StatusBadRequest) {
				t.Fatalf("invalid effort %q accepted: %v", effort, err)
			}
		}
	}
	req := &qtypes.OpenAIChatRequest{Model: "kimi-k3", ReasoningEffort: "high", Reasoning: map[string]any{"effort": "medium"}}
	if err := validateKimiReasoningEffort("kimi", req, "kimi-k3"); err != nil {
		t.Fatal("top-level precedence changed", err)
	}
	if err := validateKimiReasoningEffort("kimi", &qtypes.OpenAIChatRequest{ReasoningEffort: "medium"}, "kimi-k2.5"); err != nil {
		t.Fatal("older model contract changed", err)
	}
}
