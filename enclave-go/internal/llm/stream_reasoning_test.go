package llm

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
)

func TestOpenAIReasoningSurvivesPublicAdapters(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delta string
	}{
		{"reasoning_alias", `"reasoning":"think first"`},
		{"reasoning_content", `"reasoning_content":"think first"`},
		{"both_aliases_once", `"reasoning":"think first","reasoning_content":"think first"`},
		{"empty_content_alias", `"reasoning":"think first","reasoning_content":""`},
		{"prefer_reasoning_content", `"reasoning":"alternate","reasoning_content":"think first"`},
	} {
		for _, combined := range []bool{false, true} {
			name := tc.name + "/separate_answer"
			if combined {
				name = tc.name + "/same_chunk_answer"
			}
			t.Run(name, func(t *testing.T) {
				delta := tc.delta
				answerChunk := `data: {"choices":[{"delta":{"content":"answer"},"finish_reason":"stop"}]}`
				if combined {
					delta += `,"content":"answer"`
					answerChunk = `data: {"choices":[{"delta":{},"finish_reason":"stop"}]}`
				}
				upstream := strings.Join([]string{
					`data: {"choices":[{"delta":{` + delta + `},"finish_reason":null}]}`,
					answerChunk,
					`data: {"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":64,"total_tokens":76,"completion_tokens_details":{"reasoning_tokens":60}}}`,
					`data: [DONE]`, "",
				}, "\n")
				var native bytes.Buffer
				if err := translateOpenAIStreamToAnthropic(strings.NewReader(upstream), &native); err != nil {
					t.Fatal(err)
				}
				assertResult := func(t *testing.T, result adapter.StreamResult) {
					t.Helper()
					if result.Text != "answer" || adapter.JoinThinking(result.Thinking) != "think first" {
						t.Fatalf("content/reasoning lost or duplicated: text=%q thinking=%#v", result.Text, result.Thinking)
					}
					if result.Usage == nil || result.Usage.InputTokens != 12 || result.Usage.OutputTokens != 64 || result.Usage.ReasoningTokens != 60 {
						t.Fatalf("provider usage changed: %#v", result.Usage)
					}
				}
				t.Run("json", func(t *testing.T) {
					result, err := adapter.CollectAnthropicText(strings.NewReader(native.String()))
					if err != nil {
						t.Fatal(err)
					}
					assertResult(t, result)
					var out bytes.Buffer
					if err := adapter.WriteChatCompletionResponse(&out, "chatcmpl_test", "openai/gpt-oss-20b", result.Text, adapter.JoinThinking(result.Thinking), nil, 12, 64, result.Usage, 123, "stop"); err != nil {
						t.Fatal(err)
					}
					var response struct {
						Choices []struct {
							Message map[string]string `json:"message"`
						} `json:"choices"`
					}
					if err := json.Unmarshal(out.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					if len(response.Choices) != 1 {
						t.Fatalf("choices = %#v", response.Choices)
					}
					for _, field := range []string{"reasoning", "reasoning_content"} {
						if response.Choices[0].Message[field] != "think first" {
							t.Fatalf("%s missing from JSON response: %s", field, out.String())
						}
					}
				})
				t.Run("chat_stream", func(t *testing.T) {
					var out bytes.Buffer
					result, err := adapter.TransformStreamCaptureWithOptions(strings.NewReader(native.String()), &out, "chatcmpl_test", "openai/gpt-oss-20b", true)
					if err != nil {
						t.Fatal(err)
					}
					assertResult(t, result)
					for _, want := range []string{`"reasoning":"think first"`, `"reasoning_content":"think first"`, `"content":"answer"`, `"completion_tokens":64`, `data: [DONE]`} {
						if !strings.Contains(out.String(), want) {
							t.Fatalf("chat stream missing %s: %s", want, out.String())
						}
					}
				})
				t.Run("responses_stream", func(t *testing.T) {
					var out bytes.Buffer
					result, err := adapter.TransformResponsesStream(strings.NewReader(native.String()), &out, "resp_test", "openai/gpt-oss-20b", 12, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					assertResult(t, result)
					for _, want := range []string{"response.reasoning_text.delta", `"delta":"think first"`, "response.reasoning_text.done", `"delta":"answer"`, "response.completed", `data: [DONE]`} {
						if !strings.Contains(out.String(), want) {
							t.Fatalf("Responses stream missing %s: %s", want, out.String())
						}
					}
				})
			})
		}
	}
}
