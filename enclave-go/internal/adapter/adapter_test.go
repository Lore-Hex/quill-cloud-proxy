package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestToAnthropic(t *testing.T) {
	ptr := func(i int) *int { return &i }

	tests := []struct {
		name      string
		req       *types.OpenAIChatRequest
		want      *types.AnthropicMessagesRequest
		wantErr   bool
		errStatus int
	}{
		{
			name: "basic transformation",
			req: &types.OpenAIChatRequest{
				Messages: []types.OpenAIChatMessage{
					{Role: "user", Content: "hello"},
				},
				MaxTokens: ptr(100),
			},
			want: &types.AnthropicMessagesRequest{
				AnthropicVersion: "bedrock-2023-05-31",
				Messages: []types.AnthropicMessage{
					{Role: "user", Content: "hello"},
				},
				MaxTokens: 100,
			},
		},
		{
			name: "with system message",
			req: &types.OpenAIChatRequest{
				Messages: []types.OpenAIChatMessage{
					{Role: "system", Content: "you are a bot"},
					{Role: "user", Content: "hi"},
				},
			},
			want: &types.AnthropicMessagesRequest{
				AnthropicVersion: "bedrock-2023-05-31",
				System:           "you are a bot",
				Messages: []types.AnthropicMessage{
					{Role: "user", Content: "hi"},
				},
				MaxTokens: DefaultMaxTokens,
			},
		},
		{
			name: "multiple system messages joined",
			req: &types.OpenAIChatRequest{
				Messages: []types.OpenAIChatMessage{
					{Role: "system", Content: "part 1"},
					{Role: "system", Content: "part 2"},
					{Role: "user", Content: "hi"},
				},
			},
			want: &types.AnthropicMessagesRequest{
				AnthropicVersion: "bedrock-2023-05-31",
				System:           "part 1\n\npart 2",
				Messages: []types.AnthropicMessage{
					{Role: "user", Content: "hi"},
				},
				MaxTokens: DefaultMaxTokens,
			},
		},
		{
			name: "error empty messages",
			req: &types.OpenAIChatRequest{
				Messages: []types.OpenAIChatMessage{},
			},
			wantErr:   true,
			errStatus: 400,
		},
		{
			name: "error unsupported role",
			req: &types.OpenAIChatRequest{
				Messages: []types.OpenAIChatMessage{
					{Role: "owner", Content: "no"},
				},
			},
			wantErr:   true,
			errStatus: 400,
		},
		{
			name: "error no user/assistant turn",
			req: &types.OpenAIChatRequest{
				Messages: []types.OpenAIChatMessage{
					{Role: "system", Content: "only system"},
				},
			},
			wantErr:   true,
			errStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToAnthropic(tt.req, "model-ignored")
			if (err != nil) != tt.wantErr {
				t.Fatalf("ToAnthropic() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				var aerr *AdapterError
				if true {
					// Manually checking because asAdapterErr is in main
					if e, ok := err.(*AdapterError); ok {
						aerr = e
					}
				}
				if aerr == nil || aerr.Status != tt.errStatus {
					t.Errorf("ToAnthropic() error status = %v, want %v", aerr, tt.errStatus)
				}
				if tt.name == "error unsupported role" && !strings.Contains(aerr.Context, "role=\"owner\"") {
					t.Errorf("ToAnthropic() error context = %q, want it to contain role=\"owner\"", aerr.Context)
				}
				return
			}
			if got.System != tt.want.System {
				t.Errorf("System mismatch: got %q, want %q", got.System, tt.want.System)
			}
			if len(got.Messages) != len(tt.want.Messages) {
				t.Fatalf("Messages length mismatch: got %d, want %d", len(got.Messages), len(tt.want.Messages))
			}
			for i := range got.Messages {
				if got.Messages[i] != tt.want.Messages[i] {
					t.Errorf("Message %d mismatch: got %+v, want %+v", i, got.Messages[i], tt.want.Messages[i])
				}
			}
			if got.MaxTokens != tt.want.MaxTokens {
				t.Errorf("MaxTokens mismatch: got %d, want %d", got.MaxTokens, tt.want.MaxTokens)
			}
		})
	}
}

func TestTransformStream(t *testing.T) {
	input := `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-3","stop_reason":null,"usage":{"input_tokens":10,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}

event: message_stop
data: {"type":"message_stop"}
`
	r := strings.NewReader(input)
	w := &bytes.Buffer{}
	err := TransformStream(r, w, "id1", "model1")
	if err != nil {
		t.Fatalf("TransformStream error: %v", err)
	}

	output := w.String()
	lines := strings.Split(output, "\n\n")

	// Expecting: role chunk, "Hello" chunk, " world" chunk, finish_reason chunk, [DONE]
	// Actually TransformStream writeChunk for message_stop uses finishReason.

	var textParts []string
	foundRole := false
	foundDone := false
	var lastFinishReason any

	for _, line := range lines {
		if line == "" {
			continue
		}
		if line == "data: [DONE]" {
			foundDone = true
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			t.Errorf("line does not start with data: %q", line)
			continue
		}
		var chunk map[string]any
		if err := json.Unmarshal([]byte(line[6:]), &chunk); err != nil {
			t.Fatalf("failed to unmarshal chunk: %v", err)
		}

		choices := chunk["choices"].([]any)
		choice := choices[0].(map[string]any)
		delta := choice["delta"].(map[string]any)

		if r, ok := delta["role"]; ok && r == "assistant" {
			foundRole = true
		}
		if c, ok := delta["content"]; ok && c != "" {
			textParts = append(textParts, c.(string))
		}
		lastFinishReason = choice["finish_reason"]
	}

	if !foundRole {
		t.Error("never found role: assistant chunk")
	}
	if !foundDone {
		t.Error("never found [DONE] marker")
	}
	if strings.Join(textParts, "") != "Hello world" {
		t.Errorf("text mismatch: got %q, want %q", strings.Join(textParts, ""), "Hello world")
	}
	if lastFinishReason != "stop" {
		t.Errorf("finish_reason mismatch: got %v, want %q", lastFinishReason, "stop")
	}
}

func TestRejectUnsupportedResponsesFieldsUsesAllowlist(t *testing.T) {
	var supported map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{
		"model":"openai/gpt-4o-mini",
		"models":["openai/gpt-4o-mini"],
		"input":"hi",
		"instructions":"brief",
		"stream":true,
		"temperature":0.2,
		"top_p":0.9,
		"max_output_tokens":16,
		"max_tokens":16,
		"provider":{"only":["openai"]},
		"metadata":{"app":"test"},
		"trace":{"trace_id":"trace-1"},
		"user":"user-1",
		"safety_identifier":"user-hash",
		"session_id":"session-1",
		"store":false,
		"background":false,
		"include":[],
		"modalities":["text"],
		"parallel_tool_calls":true,
		"prompt_cache_key":"cache-bucket",
		"service_tier":"auto",
		"stream_options":{"include_usage":true},
		"text":{"format":{"type":"text"}},
		"tool_choice":"auto",
		"tools":[],
		"truncation":"disabled"
	}`), &supported); err != nil {
		t.Fatalf("unmarshal supported request: %v", err)
	}
	if err := RejectUnsupportedResponsesFields(supported); err != nil {
		t.Fatalf("supported alpha fields rejected: %v", err)
	}

	for _, tc := range []struct {
		name        string
		body        string
		wantContext string
		wantStatus  int
	}{
		{
			name:        "unsupported formatting field",
			body:        `{"model":"m","input":"hi","text":{"format":{"type":"xml"}}}`,
			wantContext: "text.format",
			wantStatus:  501,
		},
		{
			name:        "store true",
			body:        `{"model":"m","input":"hi","store":true}`,
			wantContext: "store=true",
			wantStatus:  501,
		},
		{
			name:        "non-text modality",
			body:        `{"model":"m","input":"hi","modalities":["text","audio"]}`,
			wantContext: "modalities",
			wantStatus:  501,
		},
		{
			name:        "stateful previous response",
			body:        `{"model":"m","input":"hi","previous_response_id":"resp_old"}`,
			wantContext: "previous_response_id",
			wantStatus:  501,
		},
		{
			name:        "background mode",
			body:        `{"model":"m","input":"hi","background":true}`,
			wantContext: "background=true",
			wantStatus:  501,
		},
		{
			name:        "reasoning controls",
			body:        `{"model":"m","input":"hi","reasoning":{"effort":"high"}}`,
			wantContext: "reasoning",
			wantStatus:  501,
		},
		{
			name:        "function tools are explicitly stubbed",
			body:        `{"model":"m","input":"hi","tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]}`,
			wantContext: "tools",
			wantStatus:  501,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.body), &raw); err != nil {
				t.Fatalf("unmarshal request: %v", err)
			}
			err := RejectUnsupportedResponsesFields(raw)
			if err == nil {
				t.Fatal("expected unsupported responses field error")
			}
			aerr, ok := err.(*AdapterError)
			if !ok {
				t.Fatalf("error type = %T, want *AdapterError", err)
			}
			if aerr.Status != tc.wantStatus || aerr.Context != tc.wantContext {
				t.Fatalf("adapter error = status %d context %q, want status %d context %q", aerr.Status, aerr.Context, tc.wantStatus, tc.wantContext)
			}
		})
	}
}

func TestResponsesToChatMapsStructuredTextFormat(t *testing.T) {
	req := &types.OpenAIResponsesRequest{
		Model: "moonshotai/kimi-k2.6",
		Input: "Return JSON only.",
		Text: map[string]any{
			"format": map[string]any{
				"type":   "json_schema",
				"name":   "order_status",
				"strict": true,
				"schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"status": map[string]any{"type": "string"},
					},
					"required": []any{"status"},
				},
			},
		},
	}

	chat, err := ResponsesToChat(req)
	if err != nil {
		t.Fatalf("ResponsesToChat: %v", err)
	}
	if chat.ResponseFormat["type"] != "json_schema" {
		t.Fatalf("response_format type = %#v, want json_schema", chat.ResponseFormat)
	}
	jsonSchema := chat.ResponseFormat["json_schema"].(map[string]any)
	if jsonSchema["name"] != "order_status" || jsonSchema["strict"] != true {
		t.Fatalf("json_schema metadata = %#v", jsonSchema)
	}
	schema := jsonSchema["schema"].(map[string]any)
	if schema["type"] != "object" {
		t.Fatalf("schema = %#v", schema)
	}
}

func TestResponsesToChatMapsJSONObjectFormat(t *testing.T) {
	req := &types.OpenAIResponsesRequest{
		Model: "moonshotai/kimi-k2.6",
		Input: "Return JSON only.",
		Text:  map[string]any{"format": map[string]any{"type": "json_object"}},
	}

	chat, err := ResponsesToChat(req)
	if err != nil {
		t.Fatalf("ResponsesToChat: %v", err)
	}
	if chat.ResponseFormat["type"] != "json_object" {
		t.Fatalf("response_format = %#v, want json_object", chat.ResponseFormat)
	}
}

func TestNormalizeResponsesStructuredOutputExtractsEmbeddedJSON(t *testing.T) {
	textConfig := map[string]any{"format": map[string]any{"type": "json_object"}}
	got, err := NormalizeResponsesStructuredOutput(
		"The answer is:\n{\"status\":\"ok\",\"provider\":\"kimi\"}\nDone.",
		textConfig,
	)
	if err != nil {
		t.Fatalf("NormalizeResponsesStructuredOutput: %v", err)
	}
	if got != `{"provider":"kimi","status":"ok"}` {
		t.Fatalf("normalized JSON = %q", got)
	}
}

func TestNormalizeResponsesStructuredOutputRejectsMissingJSON(t *testing.T) {
	textConfig := map[string]any{"format": map[string]any{"type": "json_schema"}}
	_, err := NormalizeResponsesStructuredOutput("status is ok", textConfig)
	if err == nil {
		t.Fatal("expected structured output error")
	}
	aerr, ok := err.(*AdapterError)
	if !ok {
		t.Fatalf("error type = %T, want *AdapterError", err)
	}
	if aerr.Status != 502 || aerr.Context != "text.format" {
		t.Fatalf("adapter error = status %d context %q, want 502 text.format", aerr.Status, aerr.Context)
	}
}

func TestResponsesToChatPreservesInputImages(t *testing.T) {
	req := &types.OpenAIResponsesRequest{
		Model: "openai/gpt-4o-mini",
		Input: []any{map[string]any{
			"role": "user",
			"content": []any{
				map[string]any{"type": "input_text", "text": "describe this"},
				map[string]any{
					"type":      "input_image",
					"image_url": "https://example.com/private-image.png",
					"detail":    "low",
				},
			},
		}},
	}

	chat, err := ResponsesToChat(req)
	if err != nil {
		t.Fatalf("ResponsesToChat: %v", err)
	}
	if len(chat.Messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(chat.Messages))
	}
	parts, ok := chat.Messages[0].Content.([]types.ChatContentPart)
	if !ok {
		t.Fatalf("content type = %T, want []ChatContentPart", chat.Messages[0].Content)
	}
	if len(parts) != 2 || parts[0].Text != "describe this" {
		t.Fatalf("bad content parts: %#v", parts)
	}
	if parts[1].ImageURL == nil || parts[1].ImageURL.URL != "https://example.com/private-image.png" || parts[1].ImageURL.Detail != "low" {
		t.Fatalf("bad image part: %#v", parts[1])
	}
	if got := types.RequestInputModalities(chat); strings.Join(got, ",") != "text,image" {
		t.Fatalf("input modalities = %#v, want text,image", got)
	}
}

func TestResponsesToChatRejectsStatefulImageFileID(t *testing.T) {
	req := &types.OpenAIResponsesRequest{
		Model: "openai/gpt-4o-mini",
		Input: []any{map[string]any{
			"role": "user",
			"content": []any{
				map[string]any{"type": "input_image", "file_id": "file_123"},
			},
		}},
	}

	errCtx := ""
	_, err := ResponsesToChat(req)
	if err != nil {
		if aerr, ok := err.(*AdapterError); ok {
			errCtx = aerr.Context
		}
	}
	if errCtx != "input_image.file_id" {
		t.Fatalf("error = %v context=%q, want input_image.file_id", err, errCtx)
	}
}

func TestRejectUnsupportedResponsesInputTokenFields(t *testing.T) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{
		"model":"openai/gpt-4o-mini",
		"input":"hi",
		"instructions":"brief",
		"text":{"format":{"type":"text"}},
		"parallel_tool_calls":true,
		"truncation":"disabled"
	}`), &raw); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if err := RejectUnsupportedResponsesInputTokenFields(raw); err != nil {
		t.Fatalf("input token request rejected: %v", err)
	}

	var stateful map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{"model":"m","input":"hi","conversation":"conv_123"}`), &stateful); err != nil {
		t.Fatalf("unmarshal stateful request: %v", err)
	}
	err := RejectUnsupportedResponsesInputTokenFields(stateful)
	if err == nil {
		t.Fatal("expected stateful input token request to be rejected")
	}
	aerr, ok := err.(*AdapterError)
	if !ok || aerr.Status != 501 || aerr.Context != "conversation" {
		t.Fatalf("error = %#v, want 501 conversation", err)
	}
}

func TestResponsesCoverageClassifiesOfficialSurface(t *testing.T) {
	wantRoutes := map[string]bool{
		"POST /v1/responses":                                         false,
		"POST /v1/responses/input_tokens":                            false,
		"GET /v1/responses/{response_id}":                            false,
		"DELETE /v1/responses/{response_id}":                         false,
		"POST /v1/responses/{response_id}/cancel":                    false,
		"POST /v1/responses/compact":                                 false,
		"GET /v1/responses/{response_id}/input_items":                false,
		"POST /v1/conversations":                                     false,
		"GET /v1/conversations/{conversation_id}":                    false,
		"PATCH /v1/conversations/{conversation_id}":                  false,
		"DELETE /v1/conversations/{conversation_id}":                 false,
		"POST /v1/conversations/{conversation_id}/items":             false,
		"GET /v1/conversations/{conversation_id}/items":              false,
		"GET /v1/conversations/{conversation_id}/items/{item_id}":    false,
		"DELETE /v1/conversations/{conversation_id}/items/{item_id}": false,
	}
	for _, item := range ResponsesCoverage {
		key := item.Method + " " + item.Path
		if _, ok := wantRoutes[key]; ok {
			wantRoutes[key] = true
		}
		if item.Kind != "stateless-real" && item.Kind != "explicit-stub" {
			t.Fatalf("route %s has invalid classification %q", key, item.Kind)
		}
	}
	for key, seen := range wantRoutes {
		if !seen {
			t.Fatalf("missing Responses coverage route %s", key)
		}
	}

	for _, field := range []string{
		"background", "conversation", "include", "input", "instructions",
		"max_output_tokens", "max_tool_calls", "metadata", "modalities",
		"parallel_tool_calls", "previous_response_id", "prompt",
		"prompt_cache_key", "prompt_cache_retention", "reasoning",
		"safety_identifier", "service_tier", "stream_options", "text",
		"tool_choice", "tools", "top_logprobs", "truncation",
	} {
		found := false
		for _, item := range ResponsesCreateFieldCoverage {
			if item.Path == field {
				found = true
				if item.Kind != "stateless-real" && item.Kind != "explicit-stub" {
					t.Fatalf("field %s has invalid classification %q", field, item.Kind)
				}
			}
		}
		if !found {
			t.Fatalf("missing Responses create field coverage for %s", field)
		}
	}
}
