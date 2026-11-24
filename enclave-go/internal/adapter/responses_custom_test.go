package adapter

import (
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

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
