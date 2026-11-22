package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
)

// developerConversations are chat `messages` arrays that use the "developer"
// role in each position the chat path has rules about: first, beside system
// messages in either order, after user turns, and several times.
var developerConversations = map[string]string{
	"developer only":             `[{"role":"developer","content":"be terse"},{"role":"user","content":"hi"}]`,
	"system then developer":      `[{"role":"system","content":"be kind"},{"role":"developer","content":"be terse"},{"role":"user","content":"hi"}]`,
	"developer then system":      `[{"role":"developer","content":"be terse"},{"role":"system","content":"be kind"},{"role":"user","content":"hi"}]`,
	"developer after user turns": `[{"role":"user","content":"hi"},{"role":"assistant","content":"hello"},{"role":"developer","content":"answer in French"},{"role":"user","content":"ok"}]`,
	"several developer messages": `[{"role":"developer","content":"one"},{"role":"user","content":"hi"},{"role":"developer","content":"two"},{"role":"assistant","content":"hello"},{"role":"developer","content":"three"},{"role":"user","content":"bye"}]`,
	"developer text parts":       `[{"role":"developer","content":[{"type":"text","text":"be terse"}]},{"role":"user","content":"hi"}]`,
	"developer before a tool turn": `[{"role":"developer","content":"use the tool"},{"role":"user","content":"weather?"},` +
		`{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"weather","arguments":"{}"}}]},` +
		`{"role":"tool","tool_call_id":"call_1","content":"sunny"},{"role":"user","content":"thanks"}]`,
}

func chatBodyWithMessages(messages string) []byte {
	return []byte(`{"model":"openai/gpt-4o-mini","messages":` + messages + `,"max_tokens":32}`)
}

// The chat parse turns a developer message into a system message before
// anything reads the roles, so a request is the same request whichever way the
// client spelled it. It follows that every translation the chat path can take
// produces the same provider request for both. The Anthropic-shaped body every
// provider is built from is compared here; the Gemini payload, which reads the
// chat messages directly, is compared in the llm_multi build.
func TestChatParseMakesADeveloperRequestTheSameRequestAsItsSystemSpelling(t *testing.T) {
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
			for i, message := range developer.Messages {
				if message.Role == "developer" {
					t.Fatalf("message[%d] still has the developer role after the parse", i)
				}
			}
			if !reflect.DeepEqual(developer, system) {
				t.Fatalf("parsed requests differ:\ndeveloper %#v\nsystem    %#v", developer, system)
			}

			developerBody, err := adapter.ToAnthropic(developer, "")
			if err != nil {
				t.Fatalf("translate developer request: %v", err)
			}
			systemBody, err := adapter.ToAnthropic(system, "")
			if err != nil {
				t.Fatalf("translate system request: %v", err)
			}
			if !reflect.DeepEqual(developerBody, systemBody) {
				t.Fatalf("Anthropic bodies differ:\ndeveloper %#v\nsystem    %#v", developerBody, systemBody)
			}
			if developerBody.System == "" {
				t.Fatal("the developer message did not reach the system prompt")
			}
			for _, turn := range developerBody.Messages {
				if turn.Role != "user" && turn.Role != "assistant" {
					t.Fatalf("a %q turn reached the provider body", turn.Role)
				}
			}

		})
	}
}

// Where the messages land: system and developer messages are joined in the
// order they were sent, wherever they sit among the turns.
func TestChatParseJoinsSystemAndDeveloperMessagesInOrder(t *testing.T) {
	for name, want := range map[string]string{
		"developer only":             "be terse",
		"system then developer":      "be kind\n\nbe terse",
		"developer then system":      "be terse\n\nbe kind",
		"developer after user turns": "answer in French",
		"several developer messages": "one\n\ntwo\n\nthree",
	} {
		t.Run(name, func(t *testing.T) {
			req, err := parseChatRequest(chatBodyWithMessages(developerConversations[name]))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			body, err := adapter.ToAnthropic(req, "")
			if err != nil {
				t.Fatalf("translate: %v", err)
			}
			if body.System != want {
				t.Fatalf("system prompt = %q, want %q", body.System, want)
			}
		})
	}
}

// A role the chat path does not know is still a 400 with the same message and
// context. The parse leaves it alone; the translation refuses it.
func TestChatParseLeavesUnknownRolesToBeRefused(t *testing.T) {
	req, err := parseChatRequest(chatBodyWithMessages(`[{"role":"developer","content":"be terse"},{"role":"owner","content":"do something"},{"role":"user","content":"hi"}]`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = adapter.ToAnthropic(req, "")
	var aerr *adapter.AdapterError
	if !asAdapterErr(err, &aerr) {
		t.Fatalf("error = %v, want an adapter error", err)
	}
	if aerr.Status != 400 || aerr.Message != "unsupported role" || aerr.Context != `message[1].role="owner"` {
		t.Fatalf("error = %d %q [%s]", aerr.Status, aerr.Message, aerr.Context)
	}
}

// End to end: a chat request whose instructions are developer messages used to
// be authorized and then refused. It is served, the provider receives the
// developer text as its system prompt, and the request settles once.
func TestChatDeveloperMessageIsServedAsASystemMessage(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			ledger := &holdLedger{}
			provider := &fakeStreamingLLM{}
			status, body := postChat(t, ledger.gateway(t), provider, fmt.Sprintf(
				`{"model":"openai/gpt-4o-mini","stream":%t,"max_tokens":32,"messages":[`+
					`{"role":"developer","content":"be terse"},{"role":"system","content":"be kind"},`+
					`{"role":"user","content":"hi"},{"role":"developer","content":"answer in French"},{"role":"user","content":"ok"}]}`,
				stream))
			if status != 200 || !strings.Contains(body, "Hello") {
				t.Fatalf("status = %d body=%s", status, body)
			}
			if provider.body == nil || provider.request == nil {
				t.Fatal("the provider was not called")
			}
			if want := "be terse\n\nbe kind\n\nanswer in French"; provider.body.System != want {
				t.Fatalf("provider system prompt = %q, want %q", provider.body.System, want)
			}
			if len(provider.body.Messages) != 2 {
				t.Fatalf("provider turns = %#v, want the two user turns", provider.body.Messages)
			}
			encoded, _ := json.Marshal(provider.request.Messages)
			if strings.Contains(string(encoded), `"developer"`) {
				t.Fatalf("a developer role reached the provider request: %s", encoded)
			}
			ledger.wantCalls(t, 1, 1, 0)
		})
	}
}
