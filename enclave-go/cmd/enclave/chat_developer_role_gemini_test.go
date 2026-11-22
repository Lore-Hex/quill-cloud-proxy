//go:build llm_multi

package main

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

// The Gemini translation builds its payload from the chat messages themselves,
// not from the Anthropic-shaped body, so it is compared separately: a developer
// request and its system spelling produce the same Gemini payload, with the
// developer text in the system instruction.
func TestChatParseGivesGeminiTheSamePayloadForDeveloperAndSystem(t *testing.T) {
	for name, messages := range developerConversations {
		t.Run(name, func(t *testing.T) {
			developer, err := parseChatRequest(chatBodyWithMessages(messages))
			if err != nil {
				t.Fatalf("parse developer request: %v", err)
			}
			system, err := parseChatRequest(chatBodyWithMessages(strings.ReplaceAll(messages, `"role":"developer"`, `"role":"system"`)))
			if err != nil {
				t.Fatalf("parse system request: %v", err)
			}
			developerBody, err := adapter.ToAnthropic(developer, "")
			if err != nil {
				t.Fatalf("translate developer request: %v", err)
			}
			systemBody, err := adapter.ToAnthropic(system, "")
			if err != nil {
				t.Fatalf("translate system request: %v", err)
			}
			developerGemini, err := llm.BuildGeminiRequestShape(context.Background(), developer, developerBody, "gemini-test")
			if err != nil {
				t.Fatalf("Gemini payload for developer request: %v", err)
			}
			systemGemini, err := llm.BuildGeminiRequestShape(context.Background(), system, systemBody, "gemini-test")
			if err != nil {
				t.Fatalf("Gemini payload for system request: %v", err)
			}
			if !reflect.DeepEqual(developerGemini, systemGemini) {
				t.Fatalf("Gemini payloads differ:\ndeveloper %#v\nsystem    %#v", developerGemini, systemGemini)
			}
			if developerGemini["systemInstruction"] == nil {
				t.Fatal("the developer message did not reach Gemini's system instruction")
			}
			for _, content := range developerGemini["contents"].([]map[string]any) {
				if role, _ := content["role"].(string); role != "user" && role != "model" {
					t.Fatalf("a %q turn reached the Gemini contents", role)
				}
			}
		})
	}
}
