package adapter

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// withRole returns messages with every `from` role rewritten to `to`.
func withRole(messages []types.OpenAIChatMessage, from, to string) []types.OpenAIChatMessage {
	out := append([]types.OpenAIChatMessage(nil), messages...)
	for i := range out {
		if out[i].Role == from {
			out[i].Role = to
		}
	}
	return out
}

// A developer message is a system message: whatever the translation does with
// a conversation, it does the same with that conversation after every
// "developer" is spelled "system". That covers where the message sits (first,
// after user turns), how many there are, and what it is refused for.
func TestNormalizeChatRolesTreatsDeveloperExactlyAsSystem(t *testing.T) {
	image := []any{map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64,AAAA"}}}
	cached := []any{map[string]any{"type": "text", "text": "cached prefix", "cache_control": map[string]any{"type": "ephemeral"}}}
	cases := []struct {
		name       string
		messages   []types.OpenAIChatMessage
		wantSystem string
		wantTurns  int
		wantError  string
	}{
		{
			name: "developer only",
			messages: []types.OpenAIChatMessage{
				{Role: "developer", Content: "be terse"},
				{Role: "user", Content: "hi"},
			},
			wantSystem: "be terse", wantTurns: 1,
		},
		{
			name: "system then developer",
			messages: []types.OpenAIChatMessage{
				{Role: "system", Content: "be kind"},
				{Role: "developer", Content: "be terse"},
				{Role: "user", Content: "hi"},
			},
			wantSystem: "be kind\n\nbe terse", wantTurns: 1,
		},
		{
			name: "developer then system",
			messages: []types.OpenAIChatMessage{
				{Role: "developer", Content: "be terse"},
				{Role: "system", Content: "be kind"},
				{Role: "user", Content: "hi"},
			},
			wantSystem: "be terse\n\nbe kind", wantTurns: 1,
		},
		{
			name: "developer after user turns",
			messages: []types.OpenAIChatMessage{
				{Role: "user", Content: "hi"},
				{Role: "assistant", Content: "hello"},
				{Role: "developer", Content: "now answer in French"},
				{Role: "user", Content: "how are you"},
			},
			wantSystem: "now answer in French", wantTurns: 3,
		},
		{
			name: "several developer messages",
			messages: []types.OpenAIChatMessage{
				{Role: "developer", Content: "one"},
				{Role: "user", Content: "hi"},
				{Role: "developer", Content: "two"},
				{Role: "assistant", Content: "hello"},
				{Role: "developer", Content: "three"},
				{Role: "user", Content: "bye"},
			},
			wantSystem: "one\n\ntwo\n\nthree", wantTurns: 3,
		},
		{
			name: "developer cache breakpoint",
			messages: []types.OpenAIChatMessage{
				{Role: "developer", Content: cached},
				{Role: "user", Content: "hi"},
			},
			wantSystem: "cached prefix", wantTurns: 1,
		},
		{
			name: "empty developer message is skipped",
			messages: []types.OpenAIChatMessage{
				{Role: "developer", Content: ""},
				{Role: "user", Content: "hi"},
			},
			wantSystem: "", wantTurns: 1,
		},
		{
			name: "developer image is refused",
			messages: []types.OpenAIChatMessage{
				{Role: "developer", Content: image},
				{Role: "user", Content: "hi"},
			},
			wantError: "system messages cannot contain images",
		},
		{
			name: "developer alone is not a conversation",
			messages: []types.OpenAIChatMessage{
				{Role: "developer", Content: "be terse"},
			},
			wantError: "messages must contain a user/assistant turn",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			developer := &types.OpenAIChatRequest{Model: "m", Messages: append([]types.OpenAIChatMessage(nil), tc.messages...)}
			NormalizeChatRoles(developer.Messages)
			for i, message := range developer.Messages {
				if message.Role == "developer" {
					t.Fatalf("message[%d] is still a developer message", i)
				}
			}
			system := &types.OpenAIChatRequest{Model: "m", Messages: withRole(tc.messages, "developer", "system")}

			got, gotErr := ToAnthropic(developer, "")
			want, wantErr := ToAnthropic(system, "")
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("developer request translated to\n%#v\nthe same request sent as system translated to\n%#v", got, want)
			}
			if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
				t.Fatalf("developer request error = %v, system request error = %v", gotErr, wantErr)
			}

			if tc.wantError != "" {
				aerr, ok := gotErr.(*AdapterError)
				if !ok || aerr.Status != 400 || aerr.Message != tc.wantError {
					t.Fatalf("error = %v, want 400 %q", gotErr, tc.wantError)
				}
				return
			}
			if gotErr != nil {
				t.Fatalf("ToAnthropic: %v", gotErr)
			}
			if got.System != tc.wantSystem {
				t.Fatalf("system prompt = %q, want %q", got.System, tc.wantSystem)
			}
			if len(got.Messages) != tc.wantTurns {
				t.Fatalf("turns = %d, want %d: %#v", len(got.Messages), tc.wantTurns, got.Messages)
			}
			for _, turn := range got.Messages {
				if turn.Role != "user" && turn.Role != "assistant" {
					t.Fatalf("a %q turn reached the provider body: %#v", turn.Role, got.Messages)
				}
			}
			if tc.name == "developer cache breakpoint" && got.SystemRaw == nil {
				t.Fatal("the developer message's cache breakpoint was dropped")
			}
		})
	}
}

// Only "developer" is an alias. Every other unknown role, a differently cased
// "Developer" included, is left as sent and refused with the message and
// context it has always had.
func TestNormalizeChatRolesLeavesUnknownRolesToBeRefused(t *testing.T) {
	for _, role := range []string{"owner", "Developer", "function", "admin"} {
		t.Run(role, func(t *testing.T) {
			req := &types.OpenAIChatRequest{Model: "m", Messages: []types.OpenAIChatMessage{
				{Role: "system", Content: "be kind"},
				{Role: role, Content: "do something"},
				{Role: "user", Content: "hi"},
			}}
			NormalizeChatRoles(req.Messages)
			if req.Messages[1].Role != role {
				t.Fatalf("role %q was rewritten to %q", role, req.Messages[1].Role)
			}
			_, err := ToAnthropic(req, "")
			aerr, ok := err.(*AdapterError)
			if !ok {
				t.Fatalf("error = %v, want an AdapterError", err)
			}
			if aerr.Status != 400 || aerr.Message != "unsupported role" {
				t.Fatalf("error = %d %q, want 400 unsupported role", aerr.Status, aerr.Message)
			}
			if !strings.Contains(aerr.Context, `message[1].role="`+role+`"`) {
				t.Fatalf("context = %q, want it to name message[1] and the role", aerr.Context)
			}
		})
	}
}

// The other roles the chat path accepts are untouched.
func TestNormalizeChatRolesKeepsSupportedRoles(t *testing.T) {
	messages := []types.OpenAIChatMessage{
		{Role: "system", Content: "s"},
		{Role: "user", Content: "u"},
		{Role: "assistant", Content: "a"},
		{Role: "tool", Content: "t", ToolCallID: "call_1"},
	}
	want := append([]types.OpenAIChatMessage(nil), messages...)
	NormalizeChatRoles(messages)
	if !reflect.DeepEqual(messages, want) {
		t.Fatalf("messages = %#v, want them unchanged", messages)
	}
	NormalizeChatRoles(nil)
}
