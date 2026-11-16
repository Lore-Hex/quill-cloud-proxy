package llm

import (
	"encoding/json"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// privatemodeReasoningWire parses chat fields the way the gateway does and
// returns the reasoning controls Privatemode is sent, or "route 400".
func privatemodeReasoningWire(t *testing.T, model, fields string) string {
	t.Helper()
	payload := []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"test"}],` + fields + `}`)
	var raw map[string]json.RawMessage
	var req qtypes.OpenAIChatRequest
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatal(err)
	}
	validation, err := adapter.ValidateChatRequestFields(raw)
	if err != nil {
		t.Fatalf("%s: %v", fields, err)
	}
	// As parseChatRequest applies a thinking switch.
	if validation.ReasoningAlias != nil {
		req.Reasoning = validation.ReasoningAlias
		req.ReasoningEffort = ""
	}
	body, err := adapter.ToAnthropic(&req, model)
	if err != nil {
		t.Fatal(err)
	}
	private := &openAICompatibleRequest{Model: model}
	if err := preparePrivatemodeWire(&req, body, private, "workspace"); err != nil {
		if status, ok := HTTPStatusFromError(err); !ok || status != 400 {
			t.Fatalf("%s: %v", fields, err)
		}
		return "route 400"
	}
	prepared, err := PrepareChatRequest("privatemode", model, &req, body, []ChatMessage{{Role: "user", Content: "test"}}, ChatPreparationOptions{ProviderCacheScope: "workspace", privateWire: private})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(prepared.Bytes, &wire); err != nil {
		t.Fatal(err)
	}
	controls := map[string]any{}
	for _, key := range []string{"reasoning", "reasoning_effort", "thinking", "enable_thinking", "chat_template_kwargs"} {
		if wire[key] != nil {
			controls[key] = wire[key]
		}
	}
	encoded, err := json.Marshal(controls)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// TestPrivatemodeThinkingSwitchWireTable records what the switch spellings
// put on the Privatemode wire today. Privatemode takes an effort only: On is
// the request without the switch, and Off is effort none where the workload
// supports it. It records current behavior, not a rule.
func TestPrivatemodeThinkingSwitchWireTable(t *testing.T) {
	for _, tc := range []struct{ model, effort, on, off string }{
		{"glm-5.3", `{"reasoning_effort":"high"}`, `{}`, `{"reasoning_effort":"none"}`},
		{"glm-5.3-flash", `{"reasoning_effort":"high"}`, `{}`, `{"reasoning_effort":"none"}`},
		{"gpt-oss-120b", `{"reasoning_effort":"high"}`, `{}`, "route 400"},
	} {
		for fields, want := range map[string]string{
			`"reasoning_effort":"high"`:                                          tc.effort,
			`"thinking":{"type":"enabled"}`:                                      tc.on,
			`"thinking":{"type":"disabled"}`:                                     tc.off,
			`"thinking":{"type":"enabled"},"reasoning_effort":"high"`:            tc.effort,
			`"enable_thinking":true,"reasoning_effort":"high"`:                   tc.effort,
			`"chat_template_kwargs":{"thinking":true},"reasoning_effort":"high"`: tc.effort,
			`"thinking":{"type":"disabled"},"reasoning_effort":"high"`:           tc.off,
			`"chat_template_kwargs":{"enable_thinking":false}`:                   tc.off,
		} {
			if got := privatemodeReasoningWire(t, tc.model, fields); got != want {
				t.Errorf("%s %s: got %s, want %s", tc.model, fields, got, want)
			}
		}
	}
}
