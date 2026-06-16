//go:build llm_multi

package llm

import (
	"context"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// TestVertexGeminiPayloadTranslatesTools covers the request side: OpenAI
// function tools become Gemini functionDeclarations, an assistant tool_call
// becomes a functionCall part, and a tool result becomes a functionResponse
// part (name correlated from the tool_call id). Without this, Gemini received no
// tools and never called them.
func TestVertexGeminiPayloadTranslatesTools(t *testing.T) {
	req := &qtypes.OpenAIChatRequest{
		Tools: []any{map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        "web_search",
				"description": "Search the web.",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{"query": map[string]any{"type": "string"}},
					"required":   []any{"query"},
				},
			},
		}},
		ToolChoice: "auto",
		Messages: []qtypes.OpenAIChatMessage{
			{Role: "user", Content: "find the newest model"},
			{Role: "assistant", ToolCalls: []qtypes.OpenAIToolCall{{
				ID:       "call_1",
				Type:     "function",
				Function: qtypes.OpenAIToolFunction{Name: "web_search", Arguments: `{"query":"newest model"}`},
			}}},
			{Role: "tool", ToolCallID: "call_1", Content: "Claude Fable 5"},
		},
	}

	payload, err := vertexGeminiPayload(context.Background(), req, nil, "gemini-3-flash-preview")
	if err != nil {
		t.Fatalf("payload: %v", err)
	}

	tools, ok := payload["tools"].([]map[string]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("payload tools = %#v, want one functionDeclarations entry", payload["tools"])
	}
	decls, ok := tools[0]["functionDeclarations"].([]map[string]any)
	if !ok || len(decls) != 1 || decls[0]["name"] != "web_search" {
		t.Fatalf("functionDeclarations = %#v", tools[0]["functionDeclarations"])
	}

	contents, ok := payload["contents"].([]map[string]any)
	if !ok || len(contents) != 3 {
		t.Fatalf("contents = %#v, want 3 turns", payload["contents"])
	}

	// assistant turn -> model role with a functionCall part
	model := contents[1]
	if model["role"] != "model" {
		t.Fatalf("contents[1].role = %v, want model", model["role"])
	}
	mParts := model["parts"].([]map[string]any)
	fc, ok := mParts[len(mParts)-1]["functionCall"].(map[string]any)
	if !ok || fc["name"] != "web_search" {
		t.Fatalf("assistant functionCall = %#v", mParts)
	}
	if args, _ := fc["args"].(map[string]any); args["query"] != "newest model" {
		t.Errorf("functionCall args = %#v", fc["args"])
	}

	// tool turn -> user role with a functionResponse part naming the function
	toolTurn := contents[2]
	tParts := toolTurn["parts"].([]map[string]any)
	fr, ok := tParts[0]["functionResponse"].(map[string]any)
	if !ok || fr["name"] != "web_search" {
		t.Fatalf("tool functionResponse = %#v", tParts)
	}
}

// TestGeminiChunkDeltaExtractsFunctionCall covers the response side: a Gemini
// functionCall part is surfaced so translateGeminiStreamToAnthropic can emit
// tool_use events.
func TestGeminiChunkDeltaExtractsFunctionCall(t *testing.T) {
	payload := `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"web_search","args":{"query":"x"}}}]},"finishReason":"STOP"}]}`
	text, calls, _, _, err := geminiChunkDelta(payload)
	if err != nil {
		t.Fatalf("delta: %v", err)
	}
	if text != "" {
		t.Errorf("text = %q, want empty", text)
	}
	if len(calls) != 1 || calls[0].Name != "web_search" {
		t.Fatalf("calls = %#v", calls)
	}
	if calls[0].Args["query"] != "x" {
		t.Errorf("args = %#v", calls[0].Args)
	}
}
