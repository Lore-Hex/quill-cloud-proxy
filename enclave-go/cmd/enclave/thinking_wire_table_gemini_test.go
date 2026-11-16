//go:build llm_multi

package main

import (
	"encoding/json"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

// geminiThinkingWire is the thinkingConfig a chat request puts on the native
// Gemini wire (Vertex and AI Studio generateContent).
func geminiThinkingWire(t *testing.T, model, fields string) string {
	t.Helper()
	req, err := parseChatRequest([]byte(`{"model":"google/` + model + `","messages":[{"role":"user","content":"test"}],` + fields + `}`))
	if err != nil {
		t.Fatalf("%s: %v", fields, err)
	}
	body, err := adapter.ToAnthropic(req, req.Model)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := llm.BuildGeminiRequestShape(t.Context(), req, body, model)
	if err != nil {
		t.Fatal(err)
	}
	config, _ := payload["generationConfig"].(map[string]any)
	encoded, err := json.Marshal(config["thinkingConfig"])
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// TestChatThinkingSwitchGeminiWireTable records what the five requests put on
// the native Gemini wire today: it reads the effort and ignores the switch.
// It records current behavior, not a rule.
func TestChatThinkingSwitchGeminiWireTable(t *testing.T) {
	for _, tc := range []struct{ model, effort, on, off string }{
		{"gemini-2.5-flash", `{"thinkingBudget":24576}`, `{"thinkingBudget":0}`, `{"thinkingBudget":0}`},
		{"gemini-3.5-flash", `{"thinkingLevel":"high"}`, `{"thinkingLevel":"minimal"}`, `{"thinkingLevel":"minimal"}`},
		{"gemini-3.8-flash", `{"thinkingLevel":"high"}`, `{"thinkingLevel":"low"}`, `{"thinkingLevel":"low"}`},
		{"gemini-3.1-pro", `{"thinkingLevel":"high"}`, `null`, `null`},
	} {
		for fields, want := range map[string]string{wireEffortOnly: tc.effort, wireOnOnly: tc.on, wireOffOnly: tc.off, wireOnEffort: tc.effort, wireOffEffort: tc.off} {
			if got := geminiThinkingWire(t, tc.model, fields); got != want {
				t.Errorf("%s %s: got %s, want %s", tc.model, fields, got, want)
			}
			for _, spelling := range wireSwitchSpellings[fields] {
				if got := geminiThinkingWire(t, tc.model, spelling); got != want {
					t.Errorf("%s %s: got %s, want %s", tc.model, spelling, got, want)
				}
			}
		}
		for _, effort := range []string{"low", "medium", "high", "xhigh", "max", "minimal"} {
			alone := geminiThinkingWire(t, tc.model, `"reasoning_effort":"`+effort+`"`)
			if got := geminiThinkingWire(t, tc.model, `"thinking":{"type":"enabled"},"reasoning_effort":"`+effort+`"`); got != alone {
				t.Errorf("%s On + %s: got %s, effort alone sends %s", tc.model, effort, got, alone)
			}
		}
	}
}
