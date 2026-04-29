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
