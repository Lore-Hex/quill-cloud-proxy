package llm

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestOpenAIStreamContentFormats(t *testing.T) {
	for _, tc := range []struct{ raw, text, thinking string }{
		{``, "", ""}, {`null`, "", ""}, {`"PONG"`, "PONG", ""}, {`[]`, "", ""},
		{`[{"type":"text","text":"PO"},{"type":"text","text":"NG"}]`, "PONG", ""},
		{`[{"type":"thinking","thinking":[{"type":"text","text":"private thought"}],"closed":true},{"type":"text","text":"PONG"}]`, "PONG", "private thought"},
	} {
		text, thinking, err := openAIStreamContent(json.RawMessage(tc.raw))
		if err != nil || text != tc.text || thinking != tc.thinking {
			t.Fatalf("content %q: got %q/%q/%v", tc.raw, text, thinking, err)
		}
	}
	for _, raw := range []string{`{}`, `42`, `[null]`, `[{"type":"unknown","text":"secret"}]`, `[{"type":"text","text":17}]`, `[{"type":"thinking","thinking":[{"type":"image","text":"secret"}]}]`} {
		text, thinking, err := openAIStreamContent(json.RawMessage(raw))
		if err == nil || text != "" || thinking != "" || strings.Contains(err.Error(), "secret") {
			t.Fatalf("malformed content was not rejected safely: %q, %v", raw, err)
		}
	}
}

func TestTranslateMistralBlocksPreservesAnswerReasoningToolsAndUsage(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":[{"type":"thinking","thinking":[{"type":"text","text":"private thought"}]}]}}]}`,
		`data: {"choices":[{"delta":{"content":[{"type":"thinking","thinking":[{"type":"text","text":" ending"}],"closed":true},{"type":"text","text":"PO"}]}}]}`,
		`data: {"choices":[{"delta":{"content":"NG"}}]}`,
		`data: {"choices":[{"delta":{"content":[],"tool_calls":[{"index":0,"id":"call_test","type":"function","function":{"name":"lookup","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":12,"completion_tokens":40,"total_tokens":52,"prompt_tokens_details":{"cached_tokens":8}}}`,
		`data: [DONE]`, "",
	}, "\n\n")
	var out bytes.Buffer
	if err := translateOpenAIStreamToAnthropicForProvider(strings.NewReader(upstream), &out, "mistral"); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	for _, want := range []string{`"thinking":"private thought"`, `"thinking":" ending"`, `"text":"PO"`, `"text":"NG"`, `"name":"lookup"`, `"stop_reason":"tool_use"`, `"input_tokens":12`, `"output_tokens":40`, `"cache_read_input_tokens":8`} {
		if !strings.Contains(body, want) {
			t.Fatalf("lost %s: %s", want, body)
		}
	}
	if strings.Contains(body, `"text":"private thought"`) {
		t.Fatal("reasoning leaked into visible answer")
	}
}

func TestTranslateMalformedContentBlockFailsInsteadOfSilentSuccess(t *testing.T) {
	var out bytes.Buffer
	err := translateOpenAIStreamToAnthropic(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":[{\"type\":\"text\",\"text\":42}]}}]}\n\ndata: [DONE]\n"), &out)
	if err == nil || strings.Contains(out.String(), `"stop_reason"`) {
		t.Fatalf("malformed content returned success: %s, %v", out.String(), err)
	}
}
