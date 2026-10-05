package llm

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func historyCases() map[string][]map[string]any {
	cases := map[string][]map[string]any{
		"thinking":          {{"type": "thinking", "thinking": "private reasoning", "signature": "signed"}},
		"redacted_thinking": {{"type": "redacted_thinking", "data": "opaque"}},
		"hosted_search":     {{"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search", "input": map[string]any{"query": "weather"}}, {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1", "content": []any{}}},
		"future_tool_use":   {{"type": "future_tool_use", "id": "future_1", "name": "hosted", "input": map[string]any{}}},
		"mcp_tool_use":      {{"type": "mcp_tool_use", "id": "mcp_1", "name": "remote", "input": map[string]any{}}},
	}
	for _, kind := range []string{"web_fetch_tool_result", "code_execution_tool_result", "bash_code_execution_tool_result", "text_editor_code_execution_tool_result", "tool_search_tool_result", "mcp_tool_result", "future_tool_result"} {
		cases[kind] = []map[string]any{{"type": kind, "tool_use_id": "srvtoolu_1", "content": "hosted output"}}
	}
	return cases
}

func historyRepresentation(t *testing.T, blocks []map[string]any, representation string) any {
	t.Helper()
	switch representation {
	case "maps":
		return blocks
	case "decoded":
		encoded, err := json.Marshal(blocks)
		if err != nil {
			t.Fatal(err)
		}
		var out []any
		if err := json.Unmarshal(encoded, &out); err != nil {
			t.Fatal(err)
		}
		return out
	case "typed":
		out := make([]qtypes.ChatContentPart, len(blocks))
		for i, block := range blocks {
			out[i] = qtypes.ChatContentPart{Type: stringValue(block["type"]), Text: stringValue(block["text"])}
		}
		return out
	default:
		t.Fatal(representation)
		return nil
	}
}

// Use the public wire projection, also used by direct/BYOK and Chutes request
// preparation, and the Responses builder downstream of that projection.
func TestProviderHistoryOpenAIWire(t *testing.T) {
	for _, responses := range []bool{false, true} {
		route := "chat"
		if responses {
			route = "responses"
		}
		for name, history := range historyCases() {
			for _, representation := range []string{"decoded", "maps", "typed"} {
				for _, role := range []string{"assistant", "user", "system", "developer"} {
					for _, withText := range []bool{false, true} {
						suffix := "/empty"
						if withText {
							suffix = "/text"
						}
						t.Run(route+"/"+name+"/"+representation+"/"+role+suffix, func(t *testing.T) {
							blocks := append([]map[string]any{}, history...)
							if withText {
								blocks = append(blocks, map[string]any{"type": "text", "text": "answer"})
							}
							body := &qtypes.AnthropicMessagesRequest{NativeContent: true, Messages: []qtypes.AnthropicMessage{{Role: role, Content: historyRepresentation(t, blocks, representation)}, {Role: "user", Content: "continue"}}}
							before, _ := json.Marshal(body)
							req := &qtypes.OpenAIChatRequest{Model: "test"}
							wire, err := BuildOpenAICompatibleRequestShape(t.Context(), req, body, "test", false)
							if err != nil {
								t.Fatalf("projection: %v", err)
							}
							messages := wire["messages"].([]any)
							want := 1
							if withText {
								want = 2
							}
							if len(messages) != want {
								t.Fatalf("messages = %#v; want %d", messages, want)
							}
							if withText {
								expected := map[string]any{"role": role, "content": []any{map[string]any{"type": "text", "text": "answer"}}}
								if !reflect.DeepEqual(messages[0], expected) {
									t.Fatalf("message = %#v; want %#v", messages[0], expected)
								}
							}
							if responses {
								encoded, _ := json.Marshal(wire)
								var chat openAICompatibleRequest
								if err := json.Unmarshal(encoded, &chat); err != nil {
									t.Fatal(err)
								}
								response, err := buildOpenAIResponsesRequest(chat)
								if err != nil {
									t.Fatal(err)
								}
								input := response["input"].([]any)
								if len(input) != want {
									t.Fatalf("input = %#v; want %d", input, want)
								}
							}
							after, _ := json.Marshal(body)
							if string(before) != string(after) {
								t.Fatal("native body mutated")
							}
						})
					}
				}
			}
		}
	}
}

func TestProviderHistoryUnsupportedOpenAI(t *testing.T) {
	for _, kind := range []string{"widget", "document"} {
		for _, representation := range []string{"decoded", "maps", "typed"} {
			t.Run(kind+"/"+representation, func(t *testing.T) {
				body := &qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: "assistant", Content: historyRepresentation(t, []map[string]any{{"type": kind}}, representation)}}}
				_, err := openAICompatibleMessagesWithFetchedImages(t.Context(), body)
				assertHistoryInputError(t, err, kind)
			})
		}
	}
}

func assertHistoryInputError(t *testing.T, err error, kind string) {
	t.Helper()
	var marker interface{ ClientInputMessage() string }
	if !errors.As(err, &marker) {
		t.Fatalf("error = %v (%T), want typed client input error for %s", err, err, kind)
	}
	if !strings.Contains(marker.ClientInputMessage(), kind) || strings.Contains(marker.ClientInputMessage(), "llm/image:") {
		t.Fatalf("client message = %q", marker.ClientInputMessage())
	}
}

func TestProviderHistoryResponsesContent(t *testing.T) {
	for name, blocks := range historyCases() {
		t.Run(name, func(t *testing.T) {
			content, err := responsesMessageContent("assistant", blocks)
			if err != nil || content != nil {
				t.Fatalf("empty projection = %#v, %v", content, err)
			}
			blocks = append(append([]map[string]any{}, blocks...), map[string]any{"type": "text", "text": "answer"})
			content, err = responsesMessageContent("assistant", blocks)
			want := []any{map[string]any{"type": "output_text", "text": "answer"}}
			if err != nil || !reflect.DeepEqual(content, want) {
				t.Fatalf("projection = %#v, %v; want %#v", content, err, want)
			}
		})
	}
	for _, kind := range []string{"widget", "document"} {
		t.Run(kind, func(t *testing.T) {
			_, err := responsesMessageContent("assistant", []map[string]any{{"type": kind}})
			assertHistoryInputError(t, err, kind)
		})
	}
}

// These are compatibility guards: these tool cases already succeed on main.
func TestProviderHistoryClientToolsCompatibility(t *testing.T) {
	call := map[string]any{"type": "tool_use", "id": "call_1", "name": "weather", "input": map[string]any{"city": "Paris"}}
	result := map[string]any{"type": "tool_result", "tool_use_id": "call_1", "content": "sunny"}
	for _, role := range []string{"assistant", "user"} {
		block := call
		if role == "user" {
			block = result
		}
		want, _ := openAICompatibleToolMessages(qtypes.AnthropicMessage{Role: role, Content: []map[string]any{block}})
		for name, history := range historyCases() {
			t.Run(role+"/"+name, func(t *testing.T) {
				blocks := append(append([]map[string]any{}, history...), block)
				// Preserve the existing permissive behavior on tool turns.
				blocks = append(blocks, map[string]any{"type": "widget"})
				got, err := openAICompatibleMessagesWithFetchedImages(t.Context(), &qtypes.AnthropicMessagesRequest{Messages: []qtypes.AnthropicMessage{{Role: role, Content: blocks}}})
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("tool projection = %#v, %v; want %#v", got, err, want)
				}
			})
		}
	}
}

func TestProviderHistoryAnthropicNative(t *testing.T) {
	png := base64.StdEncoding.EncodeToString(testPNG(t))
	cases := map[string][]map[string]any{
		"image":         {{"type": "image", "source": map[string]any{"type": "base64", "media_type": "image/png", "data": png}}},
		"tool_use":      {{"type": "tool_use", "id": "call_1", "name": "weather", "input": map[string]any{"city": "Paris"}}},
		"tool_result":   {{"type": "tool_result", "tool_use_id": "call_1", "content": "sunny"}},
		"thinking":      historyCases()["thinking"],
		"hosted_search": historyCases()["hosted_search"],
		// Native image_url stays verbatim, matching the direct route even though
		// this OpenAI-style part is not a valid native Anthropic image block.
		"image_url": {{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64," + png, "detail": "high"}}},
	}
	for _, route := range []string{"direct", "vertex", "bedrock_preprocessing_shared_wire"} {
		for name, blocks := range cases {
			t.Run(route+"/"+name, func(t *testing.T) {
				role := "assistant"
				if name == "image" || name == "image_url" || name == "tool_result" {
					role = "user"
				}
				body := &qtypes.AnthropicMessagesRequest{NativeContent: true, Messages: []qtypes.AnthropicMessage{{Role: role, Content: historyRepresentation(t, blocks, "decoded")}}}
				want, err := json.Marshal(body.Messages)
				if err != nil {
					t.Fatal(err)
				}
				var messages []qtypes.AnthropicMessage
				switch route {
				case "direct":
					messages, err = anthropicUpstreamMessages(t.Context(), body)
				case "vertex":
					messages, err = anthropicMessagesWithFetchedImages(t.Context(), body)
				case "bedrock_preprocessing_shared_wire":
					// Covers Bedrock's anthropicBodyWithFetchedImages preprocessing
					// followed by the shared buildAnthropicWireRequest, not
					// internal/bedrock.buildAnthropicBedrockWireRequest.
					var converted *qtypes.AnthropicMessagesRequest
					converted, err = anthropicBodyWithFetchedImages(t.Context(), body)
					if err == nil {
						messages = converted.Messages
					}
				}
				if err != nil {
					t.Fatalf("native projection: %v", err)
				}
				wire := buildAnthropicWireRequest("claude-test", messages, body)
				encoded, err := json.Marshal(wire)
				if err != nil {
					t.Fatal(err)
				}
				var decoded map[string]json.RawMessage
				if err := json.Unmarshal(encoded, &decoded); err != nil {
					t.Fatal(err)
				}
				if string(decoded["messages"]) != string(want) {
					t.Fatalf("native messages = %s; want %s", decoded["messages"], want)
				}
			})
		}
	}
}

func TestProviderHistoryScaleDown(t *testing.T) {
	for name, history := range historyCases() {
		for _, representation := range []string{"decoded", "maps", "typed"} {
			t.Run(name+"/"+representation, func(t *testing.T) {
				blocks := append(append([]map[string]any{}, history...), map[string]any{"type": "text", "text": "source text"})
				req := &qtypes.OpenAIChatRequest{Messages: []qtypes.OpenAIChatMessage{
					{Role: "assistant", Content: historyRepresentation(t, history, representation)},
					{Role: "user", Content: historyRepresentation(t, blocks, representation)},
				}}
				got, err := scaleDownPayload(req, "summarize")
				if err != nil {
					t.Fatalf("task projection: %v", err)
				}
				if string(got) != `{"max_tokens":4096,"text":"source text"}` {
					t.Fatalf("task body = %s", got)
				}
			})
		}
	}
	for _, representation := range []string{"decoded", "maps", "typed"} {
		t.Run("two_text_blocks/"+representation, func(t *testing.T) {
			content := historyRepresentation(t, []map[string]any{
				{"type": "text", "text": "first"},
				{"type": "text", "text": "second"},
			}, representation)
			req := &qtypes.OpenAIChatRequest{Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: content}}}
			got, err := scaleDownPayload(req, "summarize")
			if err != nil || string(got) != `{"max_tokens":4096,"text":"first\nsecond"}` {
				t.Fatalf("two text blocks = %s, %v; want newline separator", got, err)
			}
		})
	}
	for _, kind := range []string{"widget", "document"} {
		t.Run(kind, func(t *testing.T) {
			req := &qtypes.OpenAIChatRequest{Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: []any{map[string]any{"type": kind}}}}}
			_, err := scaleDownPayload(req, "summarize")
			assertHistoryInputError(t, err, kind)
			client := &openAICompatibleClient{provider: "scaledown"}
			err = client.invokeScaleDown(t.Context(), req, nil, InvokeOptions{UpstreamModel: "summarize"})
			assertHistoryInputError(t, err, kind)
		})
	}
}

func TestProviderHistoryNonObjectContent(t *testing.T) {
	for _, projection := range []string{"chat_part", "text_only"} {
		t.Run(projection, func(t *testing.T) {
			var err error
			if projection == "chat_part" {
				_, err = chatPartFromAny("not an object")
			} else {
				_, err = textOnlyContent([]any{"not an object"})
			}
			var marker interface{ ClientInputMessage() string }
			if !errors.As(err, &marker) {
				t.Fatalf("error = %v (%T), want typed client input error", err, err)
			}
			if got := marker.ClientInputMessage(); got != "content block must be an object" {
				t.Fatalf("client message = %q; want content block must be an object", got)
			}
		})
	}
}

func TestProviderHistoryUnsupportedAnthropicParts(t *testing.T) {
	for _, kind := range []string{"widget", "document"} {
		t.Run(kind, func(t *testing.T) {
			_, err := anthropicPartsWithFetchedImages(t.Context(), []qtypes.ChatContentPart{{Type: kind}})
			assertHistoryInputError(t, err, kind)
		})
	}
}
