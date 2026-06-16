package llm

import (
	"context"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// TestOpenAICompatibleMessagesReverseToolBlocks guards the round-trip bug where
// an OpenAI /chat/completions tool conversation, normalized to Anthropic
// (tool_use / tool_result blocks) and then sent back out to an OpenAI-compatible
// upstream, lost its tool structure. The upstream then received Anthropic-shaped
// blocks it could not parse and returned an empty answer after the tool turn
// (observed live with deepseek/deepseek-v4-pro; Kimi tolerated it). The body
// below is exactly what adapter.ToAnthropic emits for such a conversation.
func TestOpenAICompatibleMessagesReverseToolBlocks(t *testing.T) {
	body := &qtypes.AnthropicMessagesRequest{
		Messages: []qtypes.AnthropicMessage{
			{Role: "user", Content: "Use bash to print 6*7."},
			{Role: "assistant", Content: []map[string]any{
				{
					"type":  "tool_use",
					"id":    "call_1",
					"name":  "bash",
					"input": map[string]any{"command": "echo $((6*7))"},
				},
			}},
			{Role: "user", Content: []map[string]any{
				{"type": "tool_result", "tool_use_id": "call_1", "content": "42"},
			}},
		},
	}

	msgs, err := openAICompatibleMessagesWithFetchedImages(context.Background(), body)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("got %d messages, want 3: %+v", len(msgs), msgs)
	}

	assistant := msgs[1]
	if assistant.Role != "assistant" {
		t.Fatalf("msg[1].role = %q, want assistant", assistant.Role)
	}
	if len(assistant.ToolCalls) != 1 {
		t.Fatalf("assistant tool_calls = %d, want 1", len(assistant.ToolCalls))
	}
	call := assistant.ToolCalls[0]
	if call["id"] != "call_1" {
		t.Errorf("tool_call id = %v, want call_1", call["id"])
	}
	if call["type"] != "function" {
		t.Errorf("tool_call type = %v, want function", call["type"])
	}
	fn, ok := call["function"].(map[string]any)
	if !ok {
		t.Fatalf("tool_call function = %T, want map", call["function"])
	}
	if fn["name"] != "bash" {
		t.Errorf("function name = %v, want bash", fn["name"])
	}
	args, _ := fn["arguments"].(string)
	if !strings.Contains(args, "6*7") {
		t.Errorf("function arguments = %q, want JSON string containing the command", args)
	}

	tool := msgs[2]
	if tool.Role != "tool" {
		t.Fatalf("msg[2].role = %q, want tool", tool.Role)
	}
	if tool.ToolCallID != "call_1" {
		t.Errorf("tool_call_id = %q, want call_1", tool.ToolCallID)
	}
	if got, _ := tool.Content.(string); got != "42" {
		t.Errorf("tool content = %v, want 42", tool.Content)
	}
}

// TestOpenAICompatibleMessagesLeaveNonToolContentAlone confirms the fast-path:
// ordinary text conversations are untouched by the tool reverse-translation.
func TestOpenAICompatibleMessagesLeaveNonToolContentAlone(t *testing.T) {
	body := &qtypes.AnthropicMessagesRequest{
		System: "be terse",
		Messages: []qtypes.AnthropicMessage{
			{Role: "user", Content: "hello"},
			{Role: "assistant", Content: "hi"},
		},
	}
	msgs, err := openAICompatibleMessagesWithFetchedImages(context.Background(), body)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("got %d messages, want 3 (system+user+assistant)", len(msgs))
	}
	for _, m := range msgs {
		if len(m.ToolCalls) != 0 || m.ToolCallID != "" {
			t.Errorf("non-tool message gained tool fields: %+v", m)
		}
	}
}
