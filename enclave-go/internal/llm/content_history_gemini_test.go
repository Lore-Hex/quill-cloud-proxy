//go:build llm_multi

package llm

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestProviderHistoryGemini(t *testing.T) {
	for _, native := range []bool{false, true} {
		route := "chat"
		if native {
			route = "messages"
		}
		for name, history := range historyCases() {
			for _, representation := range []string{"decoded", "maps", "typed"} {
				for _, role := range []string{"assistant", "user", "system", "developer"} {
					t.Run(route+"/"+name+"/"+representation+"/"+role, func(t *testing.T) {
						for _, withText := range []bool{false, true} {
							blocks := append([]map[string]any{}, history...)
							if withText {
								blocks = append(blocks, map[string]any{"type": "text", "text": "answer"})
							}
							body := &qtypes.AnthropicMessagesRequest{NativeContent: native, Messages: []qtypes.AnthropicMessage{{Role: role, Content: historyRepresentation(t, blocks, representation)}, {Role: "user", Content: "continue"}}}
							req := &qtypes.OpenAIChatRequest{Model: "gemini-test", Messages: []qtypes.OpenAIChatMessage{{Role: role, Content: body.Messages[0].Content}, {Role: "user", Content: "continue"}}}
							before, _ := json.Marshal([]any{req, body})
							wire, err := vertexGeminiPayload(t.Context(), req, body, "gemini-test")
							if err != nil {
								t.Fatalf("text=%t projection: %v", withText, err)
							}
							contents := wire["contents"].([]map[string]any)
							want := 1
							if withText && role != "system" && role != "developer" {
								want = 2
							}
							if len(contents) != want {
								t.Fatalf("text=%t contents = %#v; want %d", withText, contents, want)
							}
							if withText {
								var got any
								if role == "system" || role == "developer" {
									got = wire["systemInstruction"].(map[string]any)["parts"]
								} else {
									got = contents[0]["parts"]
								}
								expected := []map[string]any{{"text": "answer"}}
								// ContentText on main does not flatten []map[string]any.
								if role == "assistant" && representation == "maps" {
									expected = []map[string]any{{"text": ""}}
								}
								if !reflect.DeepEqual(got, expected) {
									t.Fatalf("parts = %#v; want %#v", got, expected)
								}
							} else if _, ok := wire["systemInstruction"]; ok {
								t.Fatalf("empty system history survived: %#v", wire)
							}
							after, _ := json.Marshal([]any{req, body})
							if string(before) != string(after) {
								t.Fatal("input mutated")
							}
						}
					})
				}
			}
		}
	}
}

func TestProviderHistoryUnsupportedGemini(t *testing.T) {
	for _, kind := range []string{"widget", "document"} {
		for _, role := range []string{"user", "system", "developer"} {
			for _, representation := range []string{"decoded", "maps", "typed"} {
				t.Run(kind+"/"+role+"/"+representation, func(t *testing.T) {
					content := historyRepresentation(t, []map[string]any{{"type": kind}}, representation)
					req := &qtypes.OpenAIChatRequest{Messages: []qtypes.OpenAIChatMessage{{Role: role, Content: content}}}
					_, err := vertexGeminiPayload(t.Context(), req, nil, "gemini-test")
					assertHistoryInputError(t, err, kind)
				})
			}
		}
	}
}

// Assistant/model and tool/function content must retain main's permissive
// ContentText flattening, even for unsupported blocks or invalid image URLs.
func TestProviderHistoryGeminiPermissiveContent(t *testing.T) {
	for _, role := range []string{"assistant", "model", "tool", "function"} {
		for _, kind := range []string{"refusal", "image", "image_url", "widget", "document"} {
			for _, representation := range []string{"decoded", "maps", "typed"} {
				t.Run(role+"/"+kind+"/"+representation, func(t *testing.T) {
					content := historyRepresentation(t, []map[string]any{
						{"type": "thinking", "text": "private"},
						{"type": "text", "text": "first"},
						{"type": kind},
						{"type": "text", "text": "second"},
					}, representation)
					req := &qtypes.OpenAIChatRequest{Messages: []qtypes.OpenAIChatMessage{{Role: role, Name: "weather", Content: content}}}
					wire, err := vertexGeminiPayload(t.Context(), req, nil, "gemini-test")
					if err != nil {
						t.Fatalf("previously accepted content rejected: %v", err)
					}
					text := "first\nsecond"
					if representation == "maps" {
						text = "" // Preserve ContentText's existing map-slice behavior.
					}
					want := []map[string]any{{"role": "model", "parts": []map[string]any{{"text": text}}}}
					if role == "tool" || role == "function" {
						want = []map[string]any{{"role": "user", "parts": []map[string]any{{"functionResponse": map[string]any{
							"name": "weather", "response": map[string]any{"result": text},
						}}}}}
					}
					if !reflect.DeepEqual(wire["contents"], want) {
						t.Fatalf("contents = %#v; want %#v", wire["contents"], want)
					}
				})
			}
		}
	}
}

func TestProviderHistoryGeminiNativeClientTools(t *testing.T) {
	native := &adapter.AnthropicNativeRequest{Model: "google/gemini-2.5-pro", MaxTokens: 512, Messages: []qtypes.AnthropicMessage{
		{Role: "assistant", Content: []any{
			map[string]any{"type": "thinking", "thinking": "private"},
			map[string]any{"type": "tool_use", "id": "call_1", "name": "weather", "input": map[string]any{"city": "Paris"}},
			map[string]any{"type": "tool_use", "id": "call_2", "name": "temperature", "input": map[string]any{"city": "Berlin", "unit": "C"}},
		}},
		{Role: "user", Content: []any{
			map[string]any{"type": "web_search_tool_result"},
			// Reverse the results so matching by position cannot pass.
			map[string]any{"type": "tool_result", "tool_use_id": "call_2", "content": "18 C"},
			map[string]any{"type": "tool_result", "tool_use_id": "call_1", "content": "sunny"},
		}},
	}}
	body, err := adapter.MessagesToAnthropic(native)
	if err != nil {
		t.Fatal(err)
	}
	// Gemini's wire format on main omits IDs. Assert exact IDs at the shared
	// projection boundary, then assert their name/result correlation on the wire.
	calls, ok := openAICompatibleToolMessages(body.Messages[0])
	wantCalls := []chatMessage{{Role: "assistant", Content: "", ToolCalls: []map[string]any{
		{"id": "call_1", "type": "function", "function": map[string]any{"name": "weather", "arguments": `{"city":"Paris"}`}},
		{"id": "call_2", "type": "function", "function": map[string]any{"name": "temperature", "arguments": `{"city":"Berlin","unit":"C"}`}},
	}}}
	if !ok || !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("projected calls = %#v; want %#v", calls, wantCalls)
	}
	results, ok := openAICompatibleToolMessages(body.Messages[1])
	wantResults := []chatMessage{{Role: "tool", ToolCallID: "call_2", Content: "18 C"}, {Role: "tool", ToolCallID: "call_1", Content: "sunny"}}
	if !ok || !reflect.DeepEqual(results, wantResults) {
		t.Fatalf("projected results = %#v; want %#v", results, wantResults)
	}
	wire, err := vertexGeminiPayload(t.Context(), adapter.MessagesToChatShim(native), body, "gemini-2.5-pro")
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{"role": "model", "parts": []map[string]any{
			{"functionCall": map[string]any{"name": "weather", "args": map[string]any{"city": "Paris"}}, "thoughtSignature": "c2tpcA=="},
			{"functionCall": map[string]any{"name": "temperature", "args": map[string]any{"city": "Berlin", "unit": "C"}}, "thoughtSignature": "c2tpcA=="},
		}},
		{"role": "user", "parts": []map[string]any{
			{"functionResponse": map[string]any{"name": "temperature", "response": map[string]any{"result": "18 C"}}},
			{"functionResponse": map[string]any{"name": "weather", "response": map[string]any{"result": "sunny"}}},
		}},
	}
	if !reflect.DeepEqual(wire["contents"], want) {
		t.Fatalf("native tool contents = %#v; want %#v", wire["contents"], want)
	}
}

func TestProviderHistoryGeminiOnlyHistory(t *testing.T) {
	req := &qtypes.OpenAIChatRequest{Messages: []qtypes.OpenAIChatMessage{{Role: "assistant", Content: []any{map[string]any{"type": "thinking"}}}}}
	wire, err := vertexGeminiPayload(t.Context(), req, nil, "gemini-test")
	want := map[string]any{"contents": []map[string]any{{"role": "user", "parts": []map[string]any{{"text": ""}}}}}
	if err != nil || !reflect.DeepEqual(wire, want) {
		t.Fatalf("history fallback = %#v, %v; want %#v", wire, err, want)
	}
}

func TestProviderHistoryGeminiSystemOnly(t *testing.T) {
	req := &qtypes.OpenAIChatRequest{Messages: []qtypes.OpenAIChatMessage{{Role: "system", Content: "Be concise."}}}
	wire, err := vertexGeminiPayload(t.Context(), req, nil, "gemini-test")
	want := map[string]any{
		"contents":          []map[string]any{{"role": "user", "parts": []map[string]any{{"text": ""}}}},
		"systemInstruction": map[string]any{"parts": []map[string]any{{"text": "Be concise."}}},
	}
	if err != nil || !reflect.DeepEqual(wire, want) {
		t.Fatalf("system-only fallback = %#v, %v; want %#v", wire, err, want)
	}
}

// These serialized payloads are verified against main at 010251a323b1ec67a01d44d3c04210fa146af341.
// Compare bytes, not decoded JSON, to pin the complete non-native wire payload.
func TestProviderHistoryGeminiNonNativeIdentity(t *testing.T) {
	png := base64.StdEncoding.EncodeToString(testPNG(t))
	cases := []struct {
		name     string
		messages []qtypes.OpenAIChatMessage
		want     string
	}{
		{
			name: "text",
			messages: []qtypes.OpenAIChatMessage{
				{Role: "user", Content: "hello"},
				{Role: "assistant", Content: []any{map[string]any{"type": "text", "text": "first"}, map[string]any{"type": "text", "text": "second"}}},
			},
			want: `{"contents":[{"parts":[{"text":"hello"}],"role":"user"},{"parts":[{"text":"first\nsecond"}],"role":"model"}]}`,
		},
		{
			name: "image_parts",
			messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: []any{
				map[string]any{"type": "text", "text": "describe"},
				map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64," + png}},
			}}},
			want: `{"contents":[{"parts":[{"text":"describe"},{"inlineData":{"data":"` + png + `","mimeType":"image/png"}}],"role":"user"}]}`,
		},
		{
			name: "assistant_tool_calls_with_tool_results",
			messages: []qtypes.OpenAIChatMessage{
				{Role: "assistant", ToolCalls: []qtypes.OpenAIToolCall{{ID: "call_1", Type: "function", Function: qtypes.OpenAIToolFunction{Name: "weather", Arguments: `{"city":"Paris"}`}}}},
				{Role: "tool", ToolCallID: "call_1", Content: "sunny"},
			},
			want: `{"contents":[{"parts":[{"functionCall":{"args":{"city":"Paris"},"name":"weather"},"thoughtSignature":"c2tpcA=="}],"role":"model"},{"parts":[{"functionResponse":{"name":"weather","response":{"result":"sunny"}}}],"role":"user"}]}`,
		},
		{
			name:     "system_message",
			messages: []qtypes.OpenAIChatMessage{{Role: "system", Content: "Be concise."}, {Role: "user", Content: "hello"}},
			want:     `{"contents":[{"parts":[{"text":"hello"}],"role":"user"}],"systemInstruction":{"parts":[{"text":"Be concise."}]}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &qtypes.OpenAIChatRequest{Model: "google/gemini-2.5-pro", Messages: tc.messages}
			wire, err := vertexGeminiPayload(t.Context(), req, &qtypes.AnthropicMessagesRequest{NativeContent: false}, "gemini-2.5-pro")
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("payload differs from main:\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}
