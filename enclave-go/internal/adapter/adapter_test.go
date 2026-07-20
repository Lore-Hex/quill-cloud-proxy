package adapter

import (
	"bytes"
	"encoding/json"
	"reflect"
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
				MaxTokens:         100,
				MaxTokensExplicit: true,
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
			if got.MaxTokensExplicit != tt.want.MaxTokensExplicit {
				t.Errorf("MaxTokensExplicit mismatch: got %v, want %v", got.MaxTokensExplicit, tt.want.MaxTokensExplicit)
			}
		})
	}
}

func TestToAnthropicUsesNormalizedMaxTokenAliases(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantTokens   int
		wantExplicit bool
	}{
		{
			name:         "max_completion_tokens only",
			body:         `{"model":"m","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":123}`,
			wantTokens:   123,
			wantExplicit: true,
		},
		{
			name:         "max_output_tokens only",
			body:         `{"model":"m","messages":[{"role":"user","content":"hi"}],"max_output_tokens":234}`,
			wantTokens:   234,
			wantExplicit: true,
		},
		{
			name:         "none",
			body:         `{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
			wantTokens:   DefaultMaxTokens,
			wantExplicit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req types.OpenAIChatRequest
			if err := json.Unmarshal([]byte(tt.body), &req); err != nil {
				t.Fatalf("unmarshal chat request: %v", err)
			}
			req.NormalizeMaxTokens()
			got, err := ToAnthropic(&req, "model-ignored")
			if err != nil {
				t.Fatalf("ToAnthropic: %v", err)
			}
			if got.MaxTokens != tt.wantTokens {
				t.Fatalf("MaxTokens = %d, want %d", got.MaxTokens, tt.wantTokens)
			}
			if got.MaxTokensExplicit != tt.wantExplicit {
				t.Fatalf("MaxTokensExplicit = %v, want %v", got.MaxTokensExplicit, tt.wantExplicit)
			}
		})
	}
}

func TestToAnthropicNarrowsMetadataToAnthropicUserID(t *testing.T) {
	got, err := ToAnthropic(&types.OpenAIChatRequest{
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}},
		Metadata: map[string]any{
			"user_id":      "user-123",
			"internal_tag": "x",
			"foo":          42,
		},
	}, "model-ignored")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	if len(got.Metadata) != 1 || got.Metadata["user_id"] != "user-123" {
		t.Fatalf("Metadata = %#v, want only user_id", got.Metadata)
	}
	if _, ok := got.Metadata["internal_tag"]; ok {
		t.Fatalf("Metadata leaked internal_tag: %#v", got.Metadata)
	}
	if _, ok := got.Metadata["foo"]; ok {
		t.Fatalf("Metadata leaked foo: %#v", got.Metadata)
	}

	noUserID, err := ToAnthropic(&types.OpenAIChatRequest{
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}},
		Metadata: map[string]any{
			"internal_tag": "x",
			"foo":          42,
		},
	}, "model-ignored")
	if err != nil {
		t.Fatalf("ToAnthropic without user_id: %v", err)
	}
	if noUserID.Metadata != nil {
		t.Fatalf("Metadata = %#v, want nil without user_id", noUserID.Metadata)
	}
}

func TestToAnthropicMapsStopSequences(t *testing.T) {
	tests := []struct {
		name string
		stop any
		want []string
	}{
		{name: "string", stop: "END", want: []string{"END"}},
		{name: "array", stop: []any{"A", "B"}, want: []string{"A", "B"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToAnthropic(&types.OpenAIChatRequest{
				Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}},
				Stop:     tt.stop,
			}, "model-ignored")
			if err != nil {
				t.Fatalf("ToAnthropic: %v", err)
			}
			if !equalStrings(got.StopSequences, tt.want) {
				t.Fatalf("StopSequences = %#v, want %#v", got.StopSequences, tt.want)
			}
		})
	}
}

func TestToAnthropicMapsReasoningEffortToThinking(t *testing.T) {
	maxTokens := 9000
	got, err := ToAnthropic(&types.OpenAIChatRequest{
		Messages:        []types.OpenAIChatMessage{{Role: "user", Content: "think"}},
		MaxTokens:       &maxTokens,
		ReasoningEffort: "high",
	}, "model-ignored")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	thinking, ok := got.Thinking.(map[string]any)
	if !ok {
		t.Fatalf("Thinking = %#v, want map", got.Thinking)
	}
	if thinking["type"] != "enabled" {
		t.Fatalf("thinking.type = %#v, want enabled", thinking["type"])
	}
	budget, ok := thinking["budget_tokens"].(int)
	if !ok {
		t.Fatalf("budget_tokens = %#v, want int", thinking["budget_tokens"])
	}
	if budget <= 0 || budget >= got.MaxTokens {
		t.Fatalf("budget_tokens = %d, MaxTokens = %d; want budget < MaxTokens", budget, got.MaxTokens)
	}

	noThinking, err := ToAnthropic(&types.OpenAIChatRequest{
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "no reasoning"}},
	}, "model-ignored")
	if err != nil {
		t.Fatalf("ToAnthropic without reasoning: %v", err)
	}
	if noThinking.Thinking != nil {
		t.Fatalf("Thinking = %#v, want nil", noThinking.Thinking)
	}
}

func TestToAnthropicThinkingMaxTokensAreAnthropicOnly(t *testing.T) {
	maxTokens := 100
	got, err := ToAnthropic(&types.OpenAIChatRequest{
		Messages:        []types.OpenAIChatMessage{{Role: "user", Content: "think"}},
		MaxTokens:       &maxTokens,
		ReasoningEffort: "high",
	}, "model-ignored")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	if got.MaxTokens != maxTokens {
		t.Fatalf("shared MaxTokens = %d, want %d", got.MaxTokens, maxTokens)
	}
	if got.AnthropicDispatchMaxTokens() != 8292 {
		t.Fatalf("AnthropicDispatchMaxTokens = %d, want 8292", got.AnthropicDispatchMaxTokens())
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal Anthropic body: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("unmarshal Anthropic body: %v", err)
	}
	if int(payload["max_tokens"].(float64)) != 8292 {
		t.Fatalf("wire max_tokens = %#v, want 8292; payload=%s", payload["max_tokens"], encoded)
	}
}

func TestRejectUnsupportedNGlobally(t *testing.T) {
	n := 2
	req := &types.OpenAIChatRequest{
		Messages: []types.OpenAIChatMessage{{Role: "user", Content: "hi"}},
		N:        &n,
	}
	for _, tc := range []struct {
		name     string
		provider string
		model    string
	}{
		{name: "anthropic", provider: "anthropic", model: "anthropic/claude-haiku-4.5"},
		{name: "openai-compatible", provider: "openai", model: "openai/gpt-4o-mini"},
		{name: "gemini", provider: "gemini", model: "google/gemini-2.5-flash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := RejectUnsupportedNForProvider(req, tc.provider, tc.model)
			aerr, ok := err.(*AdapterError)
			if !ok {
				t.Fatalf("error = %T %v, want *AdapterError", err, err)
			}
			if aerr.Status != 400 || aerr.Message != "n>1 is not supported" || aerr.Context != "n" {
				t.Fatalf("AdapterError = %#v", aerr)
			}
		})
	}
	if _, err := ToAnthropic(req, "model-ignored"); err == nil {
		t.Fatal("ToAnthropic accepted n>1")
	}

	one := 1
	if err := RejectUnsupportedN(&types.OpenAIChatRequest{N: &one}); err != nil {
		t.Fatalf("n=1 rejected: %v", err)
	}
}

func TestToAnthropicConvertsOpenAIToolMessages(t *testing.T) {
	got, err := ToAnthropic(&types.OpenAIChatRequest{
		Messages: []types.OpenAIChatMessage{
			{Role: "user", Content: "Use setup."},
			{
				Role:    "assistant",
				Content: "",
				ToolCalls: []types.OpenAIToolCall{{
					ID:   "call_1",
					Type: "function",
					Function: types.OpenAIToolFunction{
						Name:      "setup",
						Arguments: `{}`,
					},
				}},
			},
			{
				Role:       "tool",
				ToolCallID: "call_1",
				Name:       "setup",
				Content:    `{"workspace":"/tmp/work"}`,
			},
			{Role: "assistant", Content: "Next step."},
		},
	}, "model-ignored")
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	if len(got.Messages) != 4 {
		t.Fatalf("messages = %#v", got.Messages)
	}
	assistantBlocks := got.Messages[1].Content.([]map[string]any)
	if assistantBlocks[0]["type"] != "tool_use" || assistantBlocks[0]["id"] != "call_1" || assistantBlocks[0]["name"] != "setup" {
		t.Fatalf("assistant tool_use block = %#v", assistantBlocks[0])
	}
	if input := assistantBlocks[0]["input"].(map[string]any); len(input) != 0 {
		t.Fatalf("tool input = %#v, want empty object", input)
	}
	resultBlocks := got.Messages[2].Content.([]map[string]any)
	if resultBlocks[0]["type"] != "tool_result" || resultBlocks[0]["tool_use_id"] != "call_1" || resultBlocks[0]["content"] != `{"workspace":"/tmp/work"}` {
		t.Fatalf("tool_result block = %#v", resultBlocks[0])
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

func TestMapStopReasonPreservesFilterAndLengthMarkers(t *testing.T) {
	cases := map[string]string{
		"end_turn":                             "stop",
		"stop_sequence":                        "stop",
		"max_tokens":                           "length",
		"length":                               "length",
		"content_filter":                       "content_filter",
		types.SyntheticStopReasonContentFilter: "content_filter",
		"tool_use":                             "tool_calls",
	}
	for in, want := range cases {
		if got := mapStopReason(in); got != want {
			t.Fatalf("mapStopReason(%q) = %q, want %q", in, got, want)
		}
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
		"reasoning":{"effort":"high"},
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
			name:        "hosted tools are explicitly stubbed",
			body:        `{"model":"m","input":"hi","tools":[{"type":"web_search_preview"}]}`,
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

func TestResponsesToChatMapsFunctionTools(t *testing.T) {
	req := &types.OpenAIResponsesRequest{
		Model: "moonshotai/kimi-k2.6",
		Input: "Check the weather in Paris.",
		Tools: []any{map[string]any{
			"type":        "function",
			"name":        "get_weather",
			"description": "Get weather.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"location": map[string]any{"type": "string"},
				},
				"required": []any{"location"},
			},
			"strict": true,
		}},
		ToolChoice: map[string]any{"type": "function", "name": "get_weather"},
	}

	chat, err := ResponsesToChat(req)
	if err != nil {
		t.Fatalf("ResponsesToChat: %v", err)
	}
	if len(chat.Tools) != 1 {
		t.Fatalf("tools = %d, want 1", len(chat.Tools))
	}
	tool := chat.Tools[0].(map[string]any)
	fn := tool["function"].(map[string]any)
	if tool["type"] != "function" || fn["name"] != "get_weather" || fn["strict"] != true {
		t.Fatalf("bad chat tool: %#v", tool)
	}
	choice := chat.ToolChoice.(map[string]any)
	choiceFn := choice["function"].(map[string]any)
	if choice["type"] != "function" || choiceFn["name"] != "get_weather" {
		t.Fatalf("bad tool choice: %#v", choice)
	}
}

func TestResponsesToChatMapsFunctionCallOutputContinuation(t *testing.T) {
	req := &types.OpenAIResponsesRequest{
		Model: "z-ai/glm-5.2",
		Input: []any{
			map[string]any{
				"type":      "function_call",
				"call_id":   "call_return_pong",
				"name":      "return_pong",
				"arguments": `{"value":"PONG"}`,
			},
			map[string]any{
				"type":    "function_call_output",
				"call_id": "call_return_pong",
				"output":  "PONG",
			},
		},
		Tools: []any{map[string]any{
			"type": "function",
			"name": "return_pong",
			"parameters": map[string]any{
				"type":       "object",
				"properties": map[string]any{"value": map[string]any{"type": "string"}},
			},
		}},
	}

	chat, err := ResponsesToChat(req)
	if err != nil {
		t.Fatalf("ResponsesToChat: %v", err)
	}
	if len(chat.Messages) != 2 {
		t.Fatalf("messages = %d, want 2", len(chat.Messages))
	}
	call := chat.Messages[0]
	if call.Role != "assistant" || len(call.ToolCalls) != 1 {
		t.Fatalf("function call message = %#v", call)
	}
	if got := call.ToolCalls[0]; got.ID != "call_return_pong" || got.Type != "function" ||
		got.Function.Name != "return_pong" || got.Function.Arguments != `{"value":"PONG"}` {
		t.Fatalf("function call = %#v", got)
	}
	output := chat.Messages[1]
	if output.Role != "tool" || output.ToolCallID != "call_return_pong" || output.Content != "PONG" {
		t.Fatalf("function output message = %#v", output)
	}

	anthropic, err := ToAnthropic(chat, chat.Model)
	if err != nil {
		t.Fatalf("ToAnthropic: %v", err)
	}
	if len(anthropic.Messages) != 2 {
		t.Fatalf("anthropic messages = %d, want 2", len(anthropic.Messages))
	}
	callBlocks := anthropic.Messages[0].Content.([]map[string]any)
	if len(callBlocks) != 1 || callBlocks[0]["type"] != "tool_use" ||
		callBlocks[0]["id"] != "call_return_pong" || callBlocks[0]["name"] != "return_pong" {
		t.Fatalf("anthropic function call = %#v", callBlocks)
	}
	resultBlocks := anthropic.Messages[1].Content.([]map[string]any)
	if len(resultBlocks) != 1 || resultBlocks[0]["type"] != "tool_result" ||
		resultBlocks[0]["tool_use_id"] != "call_return_pong" || resultBlocks[0]["content"] != "PONG" {
		t.Fatalf("anthropic function result = %#v", resultBlocks)
	}
}

func TestResponsesToChatRejectsMalformedFunctionContinuation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   map[string]any
		context string
	}{
		{
			name:    "missing call id",
			input:   map[string]any{"type": "function_call", "name": "return_pong", "arguments": `{}`},
			context: "input[0].call_id",
		},
		{
			name:    "invalid arguments JSON",
			input:   map[string]any{"type": "function_call", "call_id": "call_1", "name": "return_pong", "arguments": `{`},
			context: "input[0].arguments",
		},
		{
			name:    "missing output",
			input:   map[string]any{"type": "function_call_output", "call_id": "call_1"},
			context: "input[0].output",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResponsesToChat(&types.OpenAIResponsesRequest{Model: "m", Input: []any{tc.input}})
			aerr, ok := err.(*AdapterError)
			if !ok || aerr.Status != 400 || aerr.Context != tc.context {
				t.Fatalf("error = %#v, want 400 context %q", err, tc.context)
			}
		})
	}
}

func TestResponsesAcceptAndForwardReasoningConfig(t *testing.T) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{
		"model":"z-ai/glm-5.2",
		"input":"Return PONG.",
		"reasoning":{"effort":"high","summary":"auto"}
	}`), &raw); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if err := RejectUnsupportedResponsesFields(raw); err != nil {
		t.Fatalf("reasoning configuration rejected: %v", err)
	}

	reasoning := map[string]any{"effort": "high", "summary": "auto"}
	chat, err := ResponsesToChat(&types.OpenAIResponsesRequest{
		Model:     "z-ai/glm-5.2",
		Input:     "Return PONG.",
		Reasoning: reasoning,
	})
	if err != nil {
		t.Fatalf("ResponsesToChat: %v", err)
	}
	if !reflect.DeepEqual(chat.Reasoning, reasoning) {
		t.Fatalf("reasoning = %#v, want %#v", chat.Reasoning, reasoning)
	}
}

func TestResponsesRejectMalformedReasoningConfig(t *testing.T) {
	for _, value := range []string{`"high"`, `[]`, `42`} {
		var raw map[string]json.RawMessage
		body := `{"model":"m","input":"hi","reasoning":` + value + `}`
		if err := json.Unmarshal([]byte(body), &raw); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		err := RejectUnsupportedResponsesFields(raw)
		aerr, ok := err.(*AdapterError)
		if !ok || aerr.Status != 400 || aerr.Context != "reasoning" {
			t.Fatalf("reasoning=%s error = %#v, want 400 reasoning AdapterError", value, err)
		}
	}
}

func TestCollectAnthropicTextCapturesToolUse(t *testing.T) {
	stream := strings.NewReader(strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call_1","name":"get_weather","input":{}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"location\""}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":":\"Paris\"}"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n"))

	result, err := CollectAnthropicText(stream)
	if err != nil {
		t.Fatalf("CollectAnthropicText: %v", err)
	}
	if result.FinishReason != "tool_calls" {
		t.Fatalf("finish reason = %q, want tool_calls", result.FinishReason)
	}
	if len(result.ToolCalls) != 1 {
		t.Fatalf("tool calls = %#v, want one", result.ToolCalls)
	}
	call := result.ToolCalls[0]
	if call.ID != "call_1" || call.Name != "get_weather" || call.Arguments != `{"location":"Paris"}` {
		t.Fatalf("tool call = %#v", call)
	}
}

func TestCollectAnthropicTextCapturesThinking(t *testing.T) {
	// opus-4.7+ emits a thinking block (text + signature) before tool_use when
	// output_config.effort is set. The non-streaming reassembly must capture it
	// — Anthropic requires it replayed verbatim on the next tool-use turn.
	stream := strings.NewReader(strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Let me reason"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":" carefully."}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig-abc123"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"call_1","name":"exec","input":{}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{}"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":1}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n"))
	result, err := CollectAnthropicText(stream)
	if err != nil {
		t.Fatalf("CollectAnthropicText: %v", err)
	}
	if len(result.Thinking) != 1 {
		t.Fatalf("thinking blocks = %#v, want one", result.Thinking)
	}
	if result.Thinking[0].Text != "Let me reason carefully." {
		t.Fatalf("thinking text = %q", result.Thinking[0].Text)
	}
	if result.Thinking[0].Signature != "sig-abc123" {
		t.Fatalf("thinking signature = %q", result.Thinking[0].Signature)
	}
	if len(result.ToolCalls) != 1 {
		t.Fatalf("tool calls = %#v, want one (thinking must not clobber tool capture)", result.ToolCalls)
	}
}

func TestWriteChatCompletionResponseIncludesReasoningFromThinking(t *testing.T) {
	result := StreamResult{
		Text: "final answer",
		Thinking: []ThinkingBlock{
			{Text: "first thought. "},
			{Text: "second thought."},
		},
	}
	var out bytes.Buffer
	if err := WriteChatCompletionResponse(
		&out,
		"chatcmpl_reasoning",
		"anthropic/claude-opus-4.8",
		result.Text,
		JoinThinking(result.Thinking),
		nil,
		10,
		4,
		nil,
		123,
		"stop",
	); err != nil {
		t.Fatalf("WriteChatCompletionResponse: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, out.String())
	}
	choice := payload["choices"].([]any)[0].(map[string]any)
	message := choice["message"].(map[string]any)
	if got := message["content"]; got != "final answer" {
		t.Fatalf("content = %#v, want final answer", got)
	}
	wantReasoning := "first thought. second thought."
	if got := message["reasoning"]; got != wantReasoning {
		t.Fatalf("reasoning = %#v, want %q", got, wantReasoning)
	}
	if got := message["reasoning_content"]; got != wantReasoning {
		t.Fatalf("reasoning_content = %#v, want %q", got, wantReasoning)
	}
}

func TestWriteChatCompletionResponseIncludesToolCalls(t *testing.T) {
	var out bytes.Buffer
	err := WriteChatCompletionResponse(
		&out,
		"chatcmpl_tool",
		"anthropic/claude-opus-4.8",
		"",
		"tool reasoning",
		[]types.ToolCall{{ID: "call_1", CallID: "call_1", Name: "setup", Arguments: `{}`}},
		11,
		7,
		nil,
		123,
		"tool_calls",
	)
	if err != nil {
		t.Fatalf("WriteChatCompletionResponse: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, out.String())
	}
	choice := payload["choices"].([]any)[0].(map[string]any)
	if choice["finish_reason"] != "tool_calls" {
		t.Fatalf("finish_reason = %#v", choice["finish_reason"])
	}
	message := choice["message"].(map[string]any)
	if message["content"] != nil {
		t.Fatalf("content = %#v, want nil when tool_calls are present", message["content"])
	}
	if got := message["reasoning"]; got != "tool reasoning" {
		t.Fatalf("reasoning = %#v, want tool reasoning", got)
	}
	if got := message["reasoning_content"]; got != "tool reasoning" {
		t.Fatalf("reasoning_content = %#v, want tool reasoning", got)
	}
	calls := message["tool_calls"].([]any)
	if len(calls) != 1 {
		t.Fatalf("tool_calls = %#v", calls)
	}
	call := calls[0].(map[string]any)
	fn := call["function"].(map[string]any)
	if call["id"] != "call_1" || call["type"] != "function" || fn["name"] != "setup" || fn["arguments"] != `{}` {
		t.Fatalf("bad tool call response: %#v", call)
	}
}

func TestWriteChatCompletionResponseSurfacesCachedAndReasoningTokens(t *testing.T) {
	var out bytes.Buffer
	// Provider reported a prompt-cache hit (e.g. Gemini cachedContentTokenCount,
	// surfaced through CollectAnthropicText as CacheReadInputTokens) plus some
	// reasoning tokens. The non-streaming chat.completion response must surface
	// both as the OpenAI-shaped detail sub-objects — historically it dropped them.
	usage := &StreamUsage{InputTokens: 13027, OutputTokens: 5, ReasoningTokens: 3, CacheReadInputTokens: 12266}
	if err := WriteChatCompletionResponse(&out, "chatcmpl_cache", "google/gemini-3.1-pro-preview", "ok", "", nil, 13027, 5, usage, 123, "stop"); err != nil {
		t.Fatalf("WriteChatCompletionResponse: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, out.String())
	}
	u := payload["usage"].(map[string]any)
	ptd, ok := u["prompt_tokens_details"].(map[string]any)
	if !ok {
		t.Fatalf("missing prompt_tokens_details in usage=%#v", u)
	}
	if got := ptd["cached_tokens"]; got != float64(12266) {
		t.Fatalf("cached_tokens = %#v, want 12266", got)
	}
	ctd, ok := u["completion_tokens_details"].(map[string]any)
	if !ok {
		t.Fatalf("missing completion_tokens_details in usage=%#v", u)
	}
	if got := ctd["reasoning_tokens"]; got != float64(3) {
		t.Fatalf("reasoning_tokens = %#v, want 3", got)
	}
}

// When the upstream reported no cache/reasoning detail (or usage is nil on the
// estimate fallback), the detail sub-objects must be omitted, not emitted as 0.
func TestWriteChatCompletionResponseOmitsZeroDetails(t *testing.T) {
	var out bytes.Buffer
	if err := WriteChatCompletionResponse(&out, "chatcmpl_plain", "anthropic/claude-opus-4.8", "hi", "", nil, 10, 4, nil, 123, "stop"); err != nil {
		t.Fatalf("WriteChatCompletionResponse: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	u := payload["usage"].(map[string]any)
	if _, present := u["prompt_tokens_details"]; present {
		t.Fatalf("prompt_tokens_details must be omitted when no cache hit, usage=%#v", u)
	}
	if _, present := u["completion_tokens_details"]; present {
		t.Fatalf("completion_tokens_details must be omitted when no reasoning, usage=%#v", u)
	}
	choice := payload["choices"].([]any)[0].(map[string]any)
	message := choice["message"].(map[string]any)
	if _, present := message["reasoning"]; present {
		t.Fatalf("reasoning must be omitted when empty, message=%#v", message)
	}
	if _, present := message["reasoning_content"]; present {
		t.Fatalf("reasoning_content must be omitted when empty, message=%#v", message)
	}
}

func TestWriteResponsesResponseIncludesFunctionCallOutput(t *testing.T) {
	var out bytes.Buffer
	meta := &types.ResponseRequestMeta{
		Tools: []any{map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":       "get_weather",
				"parameters": map[string]any{"type": "object"},
			},
		}},
		ToolChoice: "auto",
	}
	err := WriteResponsesResponse(
		&out,
		"resp_test",
		"moonshotai/kimi-k2.6",
		"",
		[]types.ToolCall{{ID: "call_1", CallID: "call_1", Name: "get_weather", Arguments: `{"location":"Paris"}`}},
		12,
		8,
		nil,
		123,
		nil,
		meta,
	)
	if err != nil {
		t.Fatalf("WriteResponsesResponse: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	output := payload["output"].([]any)
	if len(output) != 1 {
		t.Fatalf("output = %#v, want one function_call", output)
	}
	call := output[0].(map[string]any)
	if call["type"] != "function_call" || call["name"] != "get_weather" || call["arguments"] != `{"location":"Paris"}` {
		t.Fatalf("bad function_call output: %#v", call)
	}
	if len(payload["tools"].([]any)) != 1 {
		t.Fatalf("tools not echoed: %#v", payload["tools"])
	}
}

func TestTransformResponsesStreamEmitsFunctionCallEvents(t *testing.T) {
	stream := strings.NewReader(strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call_1","name":"get_weather","input":{}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"location\":\"Paris\"}"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n"))
	var out bytes.Buffer
	result, err := TransformResponsesStream(stream, &out, "resp_test", "moonshotai/kimi-k2.6", 10, nil, nil)
	if err != nil {
		t.Fatalf("TransformResponsesStream: %v", err)
	}
	body := out.String()
	for _, want := range []string{
		"response.output_item.added",
		"response.function_call_arguments.delta",
		"response.function_call_arguments.done",
		"response.output_item.done",
		"response.completed",
		"data: [DONE]",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stream missing %s: %s", want, body)
		}
	}
	if len(result.ToolCalls) != 1 || result.ToolCalls[0].Name != "get_weather" {
		t.Fatalf("result tool calls = %#v", result.ToolCalls)
	}
	if strings.Contains(body, "response.output_text.delta") {
		t.Fatalf("tool-only stream should not emit empty text deltas: %s", body)
	}
}

func TestTransformResponsesStreamEmitsReasoningTextEvents(t *testing.T) {
	stream := strings.NewReader(strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"raw response thinking"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"visible response"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n"))
	var out bytes.Buffer
	result, err := TransformResponsesStream(stream, &out, "resp_test", "z-ai/glm-5.2", 10, nil, nil)
	if err != nil {
		t.Fatalf("TransformResponsesStream: %v", err)
	}
	body := out.String()
	for _, want := range []string{
		"response.reasoning_text.delta",
		"response.reasoning_text.done",
		`"type":"reasoning"`,
		`"delta":"raw response thinking"`,
		"response.output_text.delta",
		`"delta":"visible response"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stream missing %s: %s", want, body)
		}
	}
	if result.Text != "visible response" {
		t.Fatalf("text = %q, want visible response", result.Text)
	}
	if len(result.Thinking) != 1 || result.Thinking[0].Text != "raw response thinking" {
		t.Fatalf("thinking = %#v, want raw response thinking", result.Thinking)
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

const usageBearingAnthropicStream = `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-3","stop_reason":null,"usage":{"input_tokens":10,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}

event: message_stop
data: {"type":"message_stop"}
`

func TestTransformStreamCaptureRecordsUsageWithoutEmitting(t *testing.T) {
	var out bytes.Buffer
	result, err := TransformStreamCapture(strings.NewReader(usageBearingAnthropicStream), &out, "id1", "model1")
	if err != nil {
		t.Fatalf("TransformStreamCapture: %v", err)
	}
	if result.Usage == nil || result.Usage.InputTokens != 10 || result.Usage.OutputTokens != 2 {
		t.Fatalf("usage = %#v, want input 10 / output 2", result.Usage)
	}
	if strings.Contains(out.String(), `"usage"`) {
		t.Fatalf("usage chunk emitted without include_usage: %s", out.String())
	}
}

func TestTransformStreamCaptureWithOptionsEmitsUsageChunk(t *testing.T) {
	var out bytes.Buffer
	result, err := TransformStreamCaptureWithOptions(strings.NewReader(usageBearingAnthropicStream), &out, "id1", "model1", true)
	if err != nil {
		t.Fatalf("TransformStreamCaptureWithOptions: %v", err)
	}
	if result.Usage == nil || result.Usage.InputTokens != 10 || result.Usage.OutputTokens != 2 {
		t.Fatalf("usage = %#v, want input 10 / output 2", result.Usage)
	}

	blocks := strings.Split(strings.TrimSpace(out.String()), "\n\n")
	if len(blocks) < 3 {
		t.Fatalf("too few stream blocks: %q", out.String())
	}
	if blocks[len(blocks)-1] != "data: [DONE]" {
		t.Fatalf("last block = %q, want data: [DONE]", blocks[len(blocks)-1])
	}
	usageBlock := blocks[len(blocks)-2]
	var chunk map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(usageBlock, "data: ")), &chunk); err != nil {
		t.Fatalf("unmarshal usage chunk %q: %v", usageBlock, err)
	}
	if choices := chunk["choices"].([]any); len(choices) != 0 {
		t.Fatalf("usage chunk choices = %#v, want empty", choices)
	}
	usage := chunk["usage"].(map[string]any)
	if usage["prompt_tokens"] != float64(10) || usage["completion_tokens"] != float64(2) || usage["total_tokens"] != float64(12) {
		t.Fatalf("usage chunk = %#v", usage)
	}
	// The finish-reason chunk must still precede the usage chunk.
	var finishChunk map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(blocks[len(blocks)-3], "data: ")), &finishChunk); err != nil {
		t.Fatalf("unmarshal finish chunk: %v", err)
	}
	finishChoice := finishChunk["choices"].([]any)[0].(map[string]any)
	if finishChoice["finish_reason"] != "stop" {
		t.Fatalf("finish chunk = %#v, want finish_reason stop", finishChunk)
	}
}

func TestTransformStreamCaptureWithOptionsNoUsageNoChunk(t *testing.T) {
	stream := `event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}

event: message_stop
data: {"type":"message_stop"}
`
	var out bytes.Buffer
	result, err := TransformStreamCaptureWithOptions(strings.NewReader(stream), &out, "id1", "model1", true)
	if err != nil {
		t.Fatalf("TransformStreamCaptureWithOptions: %v", err)
	}
	if result.Usage != nil {
		t.Fatalf("usage = %#v, want nil", result.Usage)
	}
	if strings.Contains(out.String(), `"usage"`) {
		t.Fatalf("usage chunk emitted with no upstream usage: %s", out.String())
	}
}

func TestTransformStreamCaptureStreamsThinkingAsReasoningContent(t *testing.T) {
	stream := strings.NewReader(strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"raw thought"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig-1"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"visible answer"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n"))
	var out bytes.Buffer
	result, err := TransformStreamCapture(stream, &out, "id1", "model1")
	if err != nil {
		t.Fatalf("TransformStreamCapture: %v", err)
	}
	if result.Text != "visible answer" {
		t.Fatalf("text = %q, want visible answer", result.Text)
	}
	if len(result.Thinking) != 1 || result.Thinking[0].Text != "raw thought" || result.Thinking[0].Signature != "sig-1" {
		t.Fatalf("thinking = %#v, want raw thought with signature", result.Thinking)
	}
	body := out.String()
	if !strings.Contains(body, `"reasoning":"raw thought"`) ||
		!strings.Contains(body, `"reasoning_content":"raw thought"`) ||
		!strings.Contains(body, `"thinking":"raw thought"`) {
		t.Fatalf("stream did not expose thinking delta: %s", body)
	}
	if !strings.Contains(body, `"content":"visible answer"`) {
		t.Fatalf("stream missing visible content: %s", body)
	}
}

func TestTransformStreamCaptureRelayedReasoningTokens(t *testing.T) {
	// stream_translate.go relays OpenAI-compatible include_usage data on
	// the synthetic message_delta, including reasoning_tokens.
	stream := `event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"42"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":7,"output_tokens":900,"reasoning_tokens":850}}

event: message_stop
data: {"type":"message_stop"}
`
	var out bytes.Buffer
	result, err := TransformStreamCaptureWithOptions(strings.NewReader(stream), &out, "id1", "model1", true)
	if err != nil {
		t.Fatalf("TransformStreamCaptureWithOptions: %v", err)
	}
	if result.Usage == nil || result.Usage.InputTokens != 7 || result.Usage.OutputTokens != 900 || result.Usage.ReasoningTokens != 850 {
		t.Fatalf("usage = %#v, want 7/900/850", result.Usage)
	}
	if !strings.Contains(out.String(), `"reasoning_tokens":850`) {
		t.Fatalf("usage chunk missing reasoning detail: %s", out.String())
	}
}

func TestTransformStreamCaptureEmitsToolCallDeltas(t *testing.T) {
	stream := strings.NewReader(strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call_1","name":"get_weather","input":{}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"location\""}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":":\"Paris\"}"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n"))

	var out bytes.Buffer
	result, err := TransformStreamCapture(stream, &out, "id1", "model1")
	if err != nil {
		t.Fatalf("TransformStreamCapture: %v", err)
	}
	if result.FinishReason != "tool_calls" {
		t.Fatalf("finish reason = %q, want tool_calls", result.FinishReason)
	}
	if len(result.ToolCalls) != 1 {
		t.Fatalf("tool calls = %#v, want one", result.ToolCalls)
	}
	if call := result.ToolCalls[0]; call.ID != "call_1" || call.Name != "get_weather" || call.Arguments != `{"location":"Paris"}` {
		t.Fatalf("tool call = %#v", call)
	}

	var sawOpen, sawArgs bool
	var gotArgs strings.Builder
	roleFirst := false
	for i, line := range strings.Split(strings.TrimSpace(out.String()), "\n\n") {
		if line == "data: [DONE]" {
			continue
		}
		var chunk map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &chunk); err != nil {
			t.Fatalf("unmarshal chunk %q: %v", line, err)
		}
		choices := chunk["choices"].([]any)
		if len(choices) == 0 {
			continue
		}
		delta := choices[0].(map[string]any)["delta"].(map[string]any)
		if i == 0 && delta["role"] == "assistant" {
			roleFirst = true
		}
		calls, ok := delta["tool_calls"].([]any)
		if !ok {
			continue
		}
		call := calls[0].(map[string]any)
		if call["index"] != float64(0) {
			t.Fatalf("tool call index = %#v, want 0", call["index"])
		}
		fn := call["function"].(map[string]any)
		if id, ok := call["id"]; ok && id == "call_1" {
			sawOpen = true
			if fn["name"] != "get_weather" {
				t.Fatalf("opening delta name = %#v", fn["name"])
			}
		}
		if args, ok := fn["arguments"].(string); ok && args != "" {
			sawArgs = true
			gotArgs.WriteString(args)
		}
	}
	if !roleFirst {
		t.Fatalf("stream did not open with a role chunk: %s", out.String())
	}
	if !sawOpen || !sawArgs {
		t.Fatalf("missing tool_calls deltas (open=%v args=%v): %s", sawOpen, sawArgs, out.String())
	}
	if gotArgs.String() != `{"location":"Paris"}` {
		t.Fatalf("streamed arguments = %q", gotArgs.String())
	}
}

func TestTransformStreamCaptureCachedTokens(t *testing.T) {
	stream := `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","usage":{"input_tokens":400,"output_tokens":0,"cache_read_input_tokens":350,"cache_creation_input_tokens":20}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}

event: message_stop
data: {"type":"message_stop"}
`
	var out bytes.Buffer
	result, err := TransformStreamCaptureWithOptions(strings.NewReader(stream), &out, "id1", "model1", true)
	if err != nil {
		t.Fatalf("TransformStreamCaptureWithOptions: %v", err)
	}
	if result.Usage == nil || result.Usage.CacheReadInputTokens != 350 || result.Usage.CacheCreationInputTokens != 20 {
		t.Fatalf("cache usage = %#v, want 350/20", result.Usage)
	}
	if !strings.Contains(out.String(), `"prompt_tokens_details":{"cached_tokens":350}`) {
		t.Fatalf("usage chunk missing cached_tokens: %s", out.String())
	}
}

func TestWriteMessagesResponseIncludesCacheUsage(t *testing.T) {
	var out bytes.Buffer
	err := WriteMessagesResponse(&out, "msg_test", "anthropic/claude-haiku-4.5", StreamResult{
		Text:         "Hi",
		FinishReason: "stop",
		Usage:        &StreamUsage{InputTokens: 400, OutputTokens: 5, CacheReadInputTokens: 350, CacheCreationInputTokens: 20},
	}, 400, 5)
	if err != nil {
		t.Fatalf("WriteMessagesResponse: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	usage := payload["usage"].(map[string]any)
	if usage["cache_read_input_tokens"] != float64(350) || usage["cache_creation_input_tokens"] != float64(20) {
		t.Fatalf("envelope cache usage = %#v", usage)
	}
}

func TestCollectAnthropicTextCapturesUsage(t *testing.T) {
	result, err := CollectAnthropicText(strings.NewReader(usageBearingAnthropicStream))
	if err != nil {
		t.Fatalf("CollectAnthropicText: %v", err)
	}
	if result.Usage == nil || result.Usage.InputTokens != 10 || result.Usage.OutputTokens != 2 {
		t.Fatalf("usage = %#v, want input 10 / output 2", result.Usage)
	}
	if result.Text != "Hello" {
		t.Fatalf("text = %q, want Hello", result.Text)
	}
}

func TestChatStreamEmitsOptInRouterMetadataBeforeDone(t *testing.T) {
	var out bytes.Buffer
	metadata := map[string]any{"requested": "trustedrouter/auto", "attempt": 2}
	_, err := TransformStreamCaptureWithRouterMetadata(
		strings.NewReader(usageBearingAnthropicStream),
		&out,
		"chatcmpl_meta",
		"openai/gpt-4o-mini",
		true,
		metadata,
	)
	if err != nil {
		t.Fatalf("TransformStreamCaptureWithRouterMetadata: %v", err)
	}
	body := out.String()
	metadataAt := strings.Index(body, `"openrouter_metadata"`)
	doneAt := strings.Index(body, "data: [DONE]")
	if metadataAt < 0 || doneAt < 0 || metadataAt > doneAt {
		t.Fatalf("router metadata must precede DONE: %s", body)
	}
}

func TestResponsesStreamEmitsOptInRouterMetadataOnCompletedResponse(t *testing.T) {
	var out bytes.Buffer
	meta := &types.ResponseRequestMeta{
		OpenRouterMetadata: map[string]any{
			"requested": "trustedrouter/auto",
			"attempt":   1,
		},
	}
	_, err := TransformResponsesStream(
		strings.NewReader(usageBearingAnthropicStream),
		&out,
		"resp_meta",
		"openai/gpt-4o-mini",
		10,
		nil,
		meta,
	)
	if err != nil {
		t.Fatalf("TransformResponsesStream: %v", err)
	}
	body := out.String()
	completedAt := strings.Index(body, "response.completed")
	metadataAt := strings.LastIndex(body, `"openrouter_metadata"`)
	doneAt := strings.Index(body, "data: [DONE]")
	if completedAt < 0 || metadataAt < completedAt || doneAt < metadataAt {
		t.Fatalf("completed response metadata ordering is wrong: %s", body)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
