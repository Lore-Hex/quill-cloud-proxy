package llm

import (
	"encoding/json"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
)

// A native /v1/messages request carries Anthropic's thinking object, which the
// chat shim also reads as the reasoning control. First-party OpenAI chat
// completions is never sent that object: an Off is an effort, and a token
// budget, which OpenAI does not take, is a retryable route 400.
func TestNativeMessagesThinkingOnOpenAIChat(t *testing.T) {
	for _, tc := range []struct {
		model, thinking, want string
	}{
		{"gpt-5.1", `{"type":"disabled"}`, `{"reasoning_effort":"none"}`},
		{"gpt-5-nano", `{"type":"disabled"}`, "route 400"},
		{"gpt-5-nano", `{"type":"enabled","budget_tokens":2048}`, "route 400"},
		{"gpt-5.5", `{"type":"adaptive"}`, `{"reasoning_effort":"medium"}`},
		{"gpt-4o", `{"type":"disabled"}`, `{}`},
	} {
		var request adapter.AnthropicNativeRequest
		payload := `{"model":"openai/` + tc.model + `","max_tokens":4096,"messages":[{"role":"user","content":"test"}],"thinking":` + tc.thinking + `}`
		if err := json.Unmarshal([]byte(payload), &request); err != nil {
			t.Fatal(err)
		}
		body, err := adapter.MessagesToAnthropic(&request)
		if err != nil {
			t.Fatal(err)
		}
		req := adapter.MessagesToChatShim(&request)
		prepared, err := PrepareChatRequest("openai", tc.model, req, body, []ChatMessage{{Role: "user", Content: "test"}}, ChatPreparationOptions{})
		got := "route 400"
		if err != nil {
			if status, ok := HTTPStatusFromError(err); !ok || status != 400 {
				t.Fatalf("%s %s: %v", tc.model, tc.thinking, err)
			}
		} else {
			var wire map[string]any
			if err := json.Unmarshal(prepared.Bytes, &wire); err != nil {
				t.Fatal(err)
			}
			controls := map[string]any{}
			for _, key := range []string{"reasoning", "reasoning_effort", "thinking"} {
				if wire[key] != nil {
					controls[key] = wire[key]
				}
			}
			encoded, _ := json.Marshal(controls)
			got = string(encoded)
		}
		if got != tc.want {
			t.Errorf("%s %s: got %s, want %s", tc.model, tc.thinking, got, tc.want)
		}
	}
}
