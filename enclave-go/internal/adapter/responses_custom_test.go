package adapter

import (
	"encoding/json"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestNativeCustomReplayInputIsOpaque(t *testing.T) {
	for _, input := range []string{"", `{"input":"nested"}`} {
		chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "openai/gpt-5.5", Input: []any{map[string]any{"type": "custom_tool_call", "call_id": "call_same", "name": "patch", "input": input}}})
		if err != nil {
			t.Fatal(err)
		}
		if chat.Response.NativeCustom == nil || !chat.Response.NativeCustom.CallIDs["call_same"] || len(chat.Messages) != 1 || len(chat.Messages[0].ToolCalls) != 1 {
			t.Fatal("lost typed call")
		}
		call := chat.Messages[0].ToolCalls[0]
		var wrapper map[string]string
		if err := json.Unmarshal([]byte(call.Function.Arguments), &wrapper); err != nil {
			t.Fatal(err)
		}
		value, ok := wrapper["input"]
		if call.ID != "call_same" || !ok || len(wrapper) != 1 || value != input {
			t.Fatal("changed opaque tool input or ID")
		}
	}
}

func TestNativeCustomRejectsAmbiguousIDs(t *testing.T) {
	for _, kind := range []string{"custom_tool_call", "custom_tool_call_output"} {
		for _, id := range []string{"", " ", " call_123", "call_123 "} {
			item := map[string]any{"type": kind, "name": "patch", "input": "x", "output": "ok", "call_id": id}
			if _, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "openai/gpt-5.5", Input: []any{item}}); err == nil {
				t.Fatalf("accepted %s with ambiguous ID", kind)
			}
		}
	}
}

func TestNativeCustomValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*types.OpenAIResponsesRequest)
	}{
		{"invalid syntax", func(r *types.OpenAIResponsesRequest) {
			r.Tools[0].(map[string]any)["format"] = map[string]any{"type": "grammar", "syntax": "unsupported", "definition": "X"}
		}},
		{"missing grammar", func(r *types.OpenAIResponsesRequest) {
			r.Tools[0].(map[string]any)["format"] = map[string]any{"type": "grammar", "syntax": "lark"}
		}},
		{"unknown field", func(r *types.OpenAIResponsesRequest) { r.Tools[0].(map[string]any)["execute"] = true }},
		{"undeclared choice", func(r *types.OpenAIResponsesRequest) {
			r.ToolChoice = map[string]any{"type": "custom", "name": "other"}
		}},
		{"mismatched choice", func(r *types.OpenAIResponsesRequest) {
			r.ToolChoice = map[string]any{"type": "function", "name": "patch"}
		}},
		{"collision", func(r *types.OpenAIResponsesRequest) {
			r.Tools = append(r.Tools, map[string]any{"type": "function", "name": "patch"})
		}},
		{"unknown model", func(r *types.OpenAIResponsesRequest) { r.Model = "openai/gpt-99" }},
		{"deidentify", func(r *types.OpenAIResponsesRequest) { r.Deidentify = true }},
		{"hosted", func(r *types.OpenAIResponsesRequest) { r.Tools = append(r.Tools, map[string]any{"type": "web_search"}) }},
		{"mixed call id", func(r *types.OpenAIResponsesRequest) {
			r.Input = []any{map[string]any{"type": "function_call", "call_id": "c"}, map[string]any{"type": "custom_tool_call_output", "call_id": "c", "output": "ok"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &types.OpenAIResponsesRequest{Model: "openai/gpt-5.5", Input: "hello", Tools: []any{map[string]any{"type": "custom", "name": "patch"}}}
			tc.configure(req)
			if _, err := ResponsesToChat(req); err == nil {
				t.Fatal("unsupported configuration accepted")
			}
		})
	}
}
