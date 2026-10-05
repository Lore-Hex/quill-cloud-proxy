package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestResponsesInputItemsRoundTrip(t *testing.T) {
	const text = "It is sunny."
	const arguments = `{"city":"Paris"}`
	meta := &types.ResponseRequestMeta{
		WebSearchCalls: []types.ResponseWebSearchCall{{ID: "ws_1", Query: "Paris weather"}},
		OutputAnnotations: []map[string]any{{
			"type": "url_citation", "url": "https://example.test/weather", "title": "Weather",
			"start_index": 0, "end_index": len(text),
		}},
	}
	// Run the real streaming writer for a turn with reasoning, text and a call.
	stream := strings.NewReader(strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`, "",
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"thinking"}}`, "",
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`, "",
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"It is sunny."}}`, "",
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"c1","name":"weather","input":{}}}`, "",
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"city\":\"Paris\"}"}}`, "",
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":2}`, "",
		`event: message_stop`,
		`data: {"type":"message_stop"}`, "",
	}, "\n"))
	var out bytes.Buffer
	streamMeta := *meta // The writer replaces annotations with provider citations.
	result, err := TransformResponsesStream(stream, &out, "resp_roundtrip", "m", 10, nil, &streamMeta)
	if err != nil {
		t.Fatal(err)
	}
	var reasoning map[string]any
	for _, line := range strings.Split(out.String(), "\n") {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			t.Fatal(err)
		}
		if event["type"] == "response.output_item.done" {
			if item, ok := event["item"].(map[string]any); ok && item["type"] == "reasoning" {
				reasoning = item
			}
		}
	}
	if reasoning == nil || !strings.Contains(out.String(), `"text":"thinking"`) {
		t.Fatal("writer did not emit reasoning")
	}
	built := BuildResponsesObject("resp_roundtrip", "m", result.Text, result.ToolCalls, 10, 5, 0, 1, 1, "completed", nil, meta)
	// The completed builder omits reasoning; replay its output both alone and
	// with the reasoning item emitted by the streaming writer for this turn.
	for _, withReasoning := range []bool{false, true} {
		t.Run(fmt.Sprintf("reasoning=%t", withReasoning), func(t *testing.T) {
			encoded, err := json.Marshal(built)
			if err != nil {
				t.Fatal(err)
			}
			var response map[string]any
			if err := json.Unmarshal(encoded, &response); err != nil {
				t.Fatal(err)
			}
			input := response["output"].([]any)
			var itemTypes []string
			for _, item := range input {
				itemTypes = append(itemTypes, item.(map[string]any)["type"].(string))
			}
			if !reflect.DeepEqual(itemTypes, []string{"web_search_call", "message", "function_call"}) {
				t.Fatalf("builder output types = %v", itemTypes)
			}
			parts := input[1].(map[string]any)["content"].([]any)
			if len(parts[0].(map[string]any)["annotations"].([]any)) != 1 {
				t.Fatal("builder did not preserve annotation")
			}
			if withReasoning {
				input = append([]any{reasoning}, input...)
			}
			input = append(input,
				map[string]any{"type": "function_call_output", "call_id": "c1", "output": "ok"},
				map[string]any{"role": "user", "content": "And tomorrow?"})
			chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: input})
			if err != nil {
				t.Fatalf("round-trip conversion: %v", err)
			}
			want := []types.OpenAIChatMessage{
				{Role: "assistant", Content: text, ToolCalls: []types.OpenAIToolCall{{ID: "c1", Type: "function", Function: types.OpenAIToolFunction{Name: "weather", Arguments: arguments}}}},
				{Role: "tool", Content: "ok", ToolCallID: "c1"},
				{Role: "user", Content: "And tomorrow?"},
			}
			if !reflect.DeepEqual(chat.Messages, want) {
				t.Fatalf("messages = %#v, want %#v (reasoning/search must produce no messages)", chat.Messages, want)
			}
		})
	}
}

func TestResponsesInputItemsCustomTool(t *testing.T) {
	for _, tc := range []struct{ name, field, arguments string }{
		{"string", `,"input":"{\"x\":1}"`, `{"input":"{\"x\":1}"}`},
		{"object", `,"input":{"x":1}`, `{"input":{"x":1}}`},
		{"array", `,"input":[1,true,null]`, `{"input":[1,true,null]}`},
		{"number", `,"input":42`, `{"input":42}`},
		{"boolean", `,"input":false`, `{"input":false}`},
		{"null", `,"input":null`, `{"input":null}`},
		{"missing", ``, `{"input":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req types.OpenAIResponsesRequest
			body := `{"model":"m","input":[{"type":"custom_tool_call","call_id":"c1","name":"apply_patch"` + tc.field + `},
				{"type":"custom_tool_call_output","call_id":"c1","output":"ok"},
				{"type":"custom_tool_call_output","call_id":"c1","output":[{"type":"input_text","text":"part one"},{"type":"output_text","text":"part two"}]}]}`
			if err := json.Unmarshal([]byte(body), &req); err != nil {
				t.Fatal(err)
			}
			chat, err := ResponsesToChat(&req)
			if err != nil {
				t.Fatalf("custom tool conversion: %v", err)
			}
			want := []types.OpenAIChatMessage{
				{Role: "assistant", Content: "", ToolCalls: []types.OpenAIToolCall{{ID: "c1", Type: "function", Function: types.OpenAIToolFunction{Name: "apply_patch", Arguments: tc.arguments}}}},
				{Role: "tool", ToolCallID: "c1", Content: "ok"},
				{Role: "tool", ToolCallID: "c1", Content: "part one\npart two"},
			}
			if !reflect.DeepEqual(chat.Messages, want) {
				t.Fatalf("messages = %#v, want %#v", chat.Messages, want)
			}
		})
	}
}

func TestResponsesInputItemsCustomToolErrors(t *testing.T) {
	for _, tc := range []struct{ item, field, message string }{
		{`{"type":"custom_tool_call","name":"apply_patch"}`, "call_id", "custom_tool_call call_id is required"},
		{`{"type":"custom_tool_call","call_id":"c1"}`, "name", "custom_tool_call name is required"},
		{`{"type":"custom_tool_call","call_id":"  ","name":"apply_patch"}`, "call_id", "custom_tool_call call_id is required"},
		{`{"type":"custom_tool_call","call_id":"c1","name":"  "}`, "name", "custom_tool_call name is required"},
		{`{"type":"custom_tool_call_output","output":"ok"}`, "call_id", "custom_tool_call_output call_id is required"},
		{`{"type":"custom_tool_call_output","call_id":"c1"}`, "output", "custom_tool_call_output output is required"},
		{`{"type":"custom_tool_call_output","call_id":"c1","output":42}`, "output", "custom_tool_call_output output must be text or content parts"},
	} {
		t.Run(tc.item, func(t *testing.T) {
			var item any
			if err := json.Unmarshal([]byte(tc.item), &item); err != nil {
				t.Fatal(err)
			}
			_, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: []any{"hello", item}})
			aerr, ok := err.(*AdapterError)
			if !ok || aerr.Status != 400 || aerr.Context != "input[1]."+tc.field || aerr.Message != tc.message {
				t.Fatalf("error = %#v, want 400 input[1].%s: %s", err, tc.field, tc.message)
			}
		})
	}
}

func TestResponsesInputItemsUnsupported(t *testing.T) {
	for _, itemType := range []string{
		"item_reference", "local_shell_call", "local_shell_call_output", "computer_call", "computer_call_output",
		"file_search_call", "image_generation_call", "code_interpreter_call", "mcp_call", "mcp_list_tools",
		"mcp_approval_request", "mcp_approval_response", "shell_call", "shell_call_output", "apply_patch_call", "apply_patch_call_output",
	} {
		t.Run(itemType, func(t *testing.T) {
			_, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: []any{
				"hello",
				map[string]any{"type": itemType, "id": "item_1", "call_id": "c1"},
			}})
			aerr, ok := err.(*AdapterError)
			if !ok || aerr.Status != 501 || aerr.Message != "not_supported_in_alpha" || aerr.Context != "input[1]."+itemType {
				t.Fatalf("error = %#v, want 501 not_supported_in_alpha input[1].%s", err, itemType)
			}
			// Both endpoint validators precede conversion and retain the existing file refusal.
			if itemType == "file_search_call" {
				raw := map[string]json.RawMessage{"input": json.RawMessage(`[{"type":"file_search_call"}]`)}
				for _, validate := range []func(map[string]json.RawMessage) error{RejectUnsupportedResponsesFields, RejectUnsupportedResponsesInputTokenFields} {
					err := validate(raw)
					aerr, ok := err.(*AdapterError)
					if !ok || aerr.Status != 501 || aerr.Message != "not_supported_in_alpha" || aerr.Context != "file" {
						t.Fatalf("raw validation = %#v, want 501 file", err)
					}
				}
			}
		})
	}
}

func TestResponsesInputItemsTextAndCompatibility(t *testing.T) {
	// Keep compatibility controls in the same conversion as the new part types,
	// so the regression test itself fails without the fix.
	for _, part := range []string{
		`{"type":"output_text","text":"replayed","annotations":[{"type":"url_citation"}],"logprobs":[{}]}`,
		`{"type":"refusal","refusal":"replayed","text":"do not use"}`,
	} {
		t.Run(part, func(t *testing.T) {
			var req types.OpenAIResponsesRequest
			body := `{"model":"m","input":[
				{"type":"message","role":"assistant","content":[` + part + `]},
				{"type":"message","role":"assistant","content":[{"type":"input_text","text":"old parts"}]},
				{"type":"message","role":"assistant","content":"old string"},
				{"role":"user","content":"untyped"},
				{"type":"input_text","text":"bare"},
				{"type":"future_type","role":"user","content":"fallback"},
				{"role":"user","content":[{"text":"empty type"},{"type":"text","text":"text type"}]}
			]}`
			if err := json.Unmarshal([]byte(body), &req); err != nil {
				t.Fatal(err)
			}
			chat, err := ResponsesToChat(&req)
			if err != nil {
				t.Fatalf("text conversion: %v", err)
			}
			want := []types.OpenAIChatMessage{
				{Role: "assistant", Content: "replayed"}, {Role: "assistant", Content: "old parts"},
				{Role: "assistant", Content: "old string"}, {Role: "user", Content: "untyped"},
				{Role: "user", Content: "bare"}, {Role: "user", Content: "fallback"},
				{Role: "user", Content: "empty type\ntext type"},
			}
			if !reflect.DeepEqual(chat.Messages, want) {
				t.Fatalf("messages = %#v, want %#v", chat.Messages, want)
			}
		})
	}
}

func TestResponsesInputItemsDroppedOnly(t *testing.T) {
	_, emptyErr := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: []any{}})
	for _, itemType := range []string{"reasoning", "web_search_call"} {
		for _, array := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/array=%t", itemType, array), func(t *testing.T) {
				var input any = map[string]any{"type": itemType, "id": "item_1", "summary": []any{map[string]any{"type": "summary_text", "text": "thinking"}}}
				if array {
					input = []any{input, input}
				}
				chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Instructions: "x", Input: input})
				aerr, ok := err.(*AdapterError)
				if chat != nil || !ok || aerr.Status != 400 || aerr.Message != "input must contain text" || !reflect.DeepEqual(err, emptyErr) {
					t.Fatalf("chat = %#v, error = %#v, want empty-input error %#v", chat, err, emptyErr)
				}
			})
		}
	}
}

func TestResponsesInputItemsAssistantTurns(t *testing.T) {
	call := func(id string) any {
		return map[string]any{"type": "function_call", "call_id": id, "name": "weather", "arguments": "{}"}
	}
	toolCall := func(id string) types.OpenAIToolCall {
		return types.OpenAIToolCall{ID: id, Type: "function", Function: types.OpenAIToolFunction{Name: "weather", Arguments: "{}"}}
	}
	folded := types.OpenAIChatMessage{Role: "assistant", Content: "", ToolCalls: []types.OpenAIToolCall{toolCall("c1"), toolCall("c2")}}
	// Barrier/order controls share an assertion with a parallel call turn, so
	// each case catches the round-2 regression as well as preserving order.
	for _, tc := range []struct {
		name  string
		input []any
		want  []types.OpenAIChatMessage
	}{
		{"parallel functions", []any{call("c1"), call("c2")}, []types.OpenAIChatMessage{folded}},
		{"function then custom", []any{call("c1"), map[string]any{"type": "custom_tool_call", "call_id": "c2", "name": "apply_patch", "input": "x"}},
			[]types.OpenAIChatMessage{{Role: "assistant", Content: "", ToolCalls: []types.OpenAIToolCall{toolCall("c1"), {ID: "c2", Type: "function", Function: types.OpenAIToolFunction{Name: "apply_patch", Arguments: `{"input":"x"}`}}}}}},
		{"output ends turn", []any{call("c1"), call("c2"), map[string]any{"type": "function_call_output", "call_id": "c2", "output": "ok"}, call("c3")},
			[]types.OpenAIChatMessage{folded, {Role: "tool", Content: "ok", ToolCallID: "c2"}, {Role: "assistant", Content: "", ToolCalls: []types.OpenAIToolCall{toolCall("c3")}}}},
		{"later text stays separate", []any{call("c1"), call("c2"), map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": "later"}}}},
			[]types.OpenAIChatMessage{folded, {Role: "assistant", Content: "later"}}},
		{"user ends turn", []any{call("c1"), call("c2"), map[string]any{"role": "user", "content": "continue"}, call("c3")},
			[]types.OpenAIChatMessage{folded, {Role: "user", Content: "continue"}, {Role: "assistant", Content: "", ToolCalls: []types.OpenAIToolCall{toolCall("c3")}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			messages, err := responseInputMessages(tc.input)
			if err != nil || !reflect.DeepEqual(messages, tc.want) {
				t.Fatalf("messages = %#v, error = %v, want %#v", messages, err, tc.want)
			}
		})
	}
}

func TestResponsesInputItemsEmptyAssistantText(t *testing.T) {
	// Replay the actual empty output emitted by the completed response builder.
	built := BuildResponsesObject("resp_empty", "m", "", nil, 0, 0, 0, 1, 1, "completed", nil, nil)
	encoded, err := json.Marshal(built)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		item any
	}{
		{"builder output", response["output"].([]any)[0]},
		{"multiple empty text parts", map[string]any{"type": "message", "role": "assistant", "content": []any{
			map[string]any{"type": "output_text", "text": ""}, map[string]any{"type": "input_text", "text": ""},
			map[string]any{"type": "text", "text": ""}, map[string]any{"text": ""},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: []any{tc.item, "continue"}})
			// Keep existing user-empty and literal-empty-array behavior in the
			// same assertion as the newly accepted empty assistant replay.
			_, userErr := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: []any{map[string]any{
				"type": "message", "role": "user", "content": tc.item.(map[string]any)["content"],
			}}})
			empty, emptyErr := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Instructions: "x", Input: []any{}})
			if err != nil || chat == nil || !reflect.DeepEqual(chat.Messages, []types.OpenAIChatMessage{{Role: "user", Content: "continue"}}) ||
				!reflect.DeepEqual(userErr, &AdapterError{Status: 400, Message: "input item must contain text or image"}) ||
				emptyErr != nil || empty == nil || !reflect.DeepEqual(empty.Messages, []types.OpenAIChatMessage{{Role: "system", Content: "x"}}) {
				t.Errorf("replay = %#v, error = %v; user error = %v; empty array = %#v, error = %v", chat, err, userErr, empty, emptyErr)
			}
			for _, instructions := range []string{"", "x"} {
				for _, array := range []bool{false, true} {
					t.Run(fmt.Sprintf("dropped-only/instructions=%q/array=%t", instructions, array), func(t *testing.T) {
						var input any = tc.item
						if array {
							input = []any{input}
						}
						chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Instructions: instructions, Input: input})
						if chat != nil || !reflect.DeepEqual(err, &AdapterError{Status: 400, Message: "input must contain text"}) {
							t.Fatalf("chat = %#v, error = %#v, want empty-input 400", chat, err)
						}
					})
				}
			}
		})
	}
}
