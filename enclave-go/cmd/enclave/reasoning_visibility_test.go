package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type visibilityLLM struct{ request *types.OpenAIChatRequest }

func (f *visibilityLLM) InvokeStreaming(_ context.Context, req *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	f.request = req
	_, err := io.WriteString(out, `event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"private-thought"}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"42"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":7,"output_tokens":900,"reasoning_tokens":850}}

event: message_stop
data: {"type":"message_stop"}

`)
	return err
}

func TestServeChatIncludeReasoningFiltersOnlyPublicOutput(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, include := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%v/include=%v", stream, include), func(t *testing.T) {
				bearer := "visibility-test"
				digest := sha256.Sum256([]byte(bearer))
				reg := auth.New([]types.DeviceConfig{{KeyHash: hex.EncodeToString(digest[:]), Owner: "test", DeviceID: "visibility"}})
				provider := &visibilityLLM{}
				server, client := net.Pipe()
				defer client.Close()
				done := make(chan struct{})
				go func() { defer close(done); serveOne(context.Background(), server, reg, provider, nil, nil, nil, nil) }()
				requestBody := fmt.Sprintf(`{"model":"z-ai/glm-5.2","messages":[{"role":"user","content":"6*7?"}],"reasoning":{"effort":"high"},"include_reasoning":%v,"stream":%v,"stream_options":{"include_usage":true}}`, include, stream)
				if _, err := fmt.Fprintf(client, "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", bearer, len(requestBody), requestBody); err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(bufio.NewReader(client), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				<-done
				if resp.StatusCode != 200 {
					t.Fatalf("status %d: %s", resp.StatusCode, body)
				}
				if strings.Contains(string(body), "private-thought") != include {
					t.Fatalf("visibility mismatch: %s", body)
				}
				if !strings.Contains(string(body), `"reasoning_tokens":850`) || !strings.Contains(string(body), `"completion_tokens":900`) {
					t.Fatalf("billing usage changed: %s", body)
				}
				if provider.request == nil || provider.request.Reasoning.(map[string]any)["effort"] != "high" {
					t.Fatal("thinking controls changed")
				}
				wire, _ := json.Marshal(provider.request)
				if strings.Contains(string(wire), "include_reasoning") || strings.Contains(string(wire), "ExcludeReasoning") {
					t.Fatal("router visibility leaked upstream")
				}
			})
		}
	}
}

func TestReasoningVisibilityAppliesToOrchestrationDetails(t *testing.T) {
	item := fusionCallResult{ExcludeReasoning: true, RawText: "<think>private-thought</think>42", Result: adapter.StreamResult{Text: "42", Thinking: []adapter.ThinkingBlock{{Text: "private-thought", Signature: "signature"}}, Usage: &adapter.StreamUsage{ReasoningTokens: 850}}, Rescue: &fusionOverthinkingRescue{Thinking: "private-rescue", ThinkingTokens: 8}}
	for _, detail := range []map[string]any{fusionCallDetails(item), advisorSafeCallDetails(item, true)} {
		wire, _ := json.Marshal(detail)
		if strings.Contains(string(wire), "private-") || strings.Contains(string(wire), "signature") {
			t.Fatal(string(wire))
		}
		if detail["reasoning_tokens"] != 850 || detail["aborted_thinking_tokens"] != 8 {
			t.Fatal("lost usage counters")
		}
	}
	if item.Result.Thinking[0].Text != "private-thought" {
		t.Fatal("internal reasoning was mutated")
	}
	var out bytes.Buffer
	emitter := newAdvisorStreamEmitter(&out, "id", "model", 1)
	emitter.excludeReasoning = true
	observe := emitter.Observer("worker", 0, "model")
	observe(adapter.StreamDelta{Type: "thinking_delta", Text: "private-thought"})
	observe(adapter.StreamDelta{Type: "signature_delta", Signature: "signature"})
	observe(adapter.StreamDelta{Type: "text_delta", Text: "42"})
	if strings.Contains(out.String(), "private-") || strings.Contains(out.String(), "signature") || !strings.Contains(out.String(), "42") {
		t.Fatal(out.String())
	}
}

func TestReasoningVisibilityWebSearchEmitters(t *testing.T) {
	req := &types.OpenAIChatRequest{ExcludeReasoning: true}
	var out bytes.Buffer
	emitter := newChatWebSearchEmitter(&out, "id", "model", req)
	emitter.Observe(adapter.StreamDelta{Type: "thinking_delta", Text: "private-thought"})
	emitter.Observe(adapter.StreamDelta{Type: "text_delta", Text: "42"})
	if strings.Contains(out.String(), "private-thought") || !strings.Contains(out.String(), "42") {
		t.Fatal(out.String())
	}
}

func TestResponsesReasoningExcludeIsConsumedLocally(t *testing.T) {
	req, err := parseResponsesRequest([]byte(`{"model":"model","input":"hi","reasoning":{"exclude":true,"effort":"high"}}`))
	if err != nil {
		t.Fatal(err)
	}
	chat, err := adapter.ResponsesToChat(req)
	if err != nil {
		t.Fatal(err)
	}
	if !chat.ExcludeReasoning {
		t.Fatal("visibility missing")
	}
	encoded, _ := json.Marshal(chat.Reasoning)
	if string(encoded) != `{"effort":"high"}` {
		t.Fatal(string(encoded))
	}
}
