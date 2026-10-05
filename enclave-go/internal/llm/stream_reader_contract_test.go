package llm

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

// These contracts belong to the provider readers, formerly internal/sse.
func TestOpenAIReaderLineEndingsAndQueuedEvents(t *testing.T) {
	for _, separator := range []string{"\n", "\n\n"} {
		for _, end := range []string{"", "\n", "\n\n"} {
			for _, newline := range []string{"\n", "\r\n"} {
				t.Run(strings.NewReplacer("\r", "CR", "\n", "LF").Replace(separator+"/"+end+"/"+newline), func(t *testing.T) {
					data := []string{`{"choices":[{"delta":{"content":"first"}}]}`, `{"choices":[{"delta":{"content":"second"}}]}`, `{"usage":{"prompt_tokens":5,"completion_tokens":2}}`, `[DONE]`}
					wire := "event: ignored\nid: 7\n: comment\nretry: 42\ndata: " + strings.Join(data, separator+"data: ") + end
					var out bytes.Buffer
					err := translateOpenAIStreamToAnthropic(strings.NewReader(strings.ReplaceAll(wire, "\n", newline)), &out)
					if err != nil || strings.Count(out.String(), `"text":"first"`) != 1 || strings.Count(out.String(), `"text":"second"`) != 1 || strings.Count(out.String(), "event: message_stop") != 1 {
						t.Fatalf("queued content: err=%v out=%s", err, &out)
					}
				})
			}
		}
	}
	for _, end := range []string{"", "\n", "\n\n"} {
		var out bytes.Buffer
		wire := "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\ndata: {\"error\":{\"code\":403,\"message\":\"refusal\"}}\ndata: [DONE]" + end
		err := translateOpenAIStreamToAnthropic(strings.NewReader(wire), &out)
		d := upstreamerror.Parse(err)
		if err == nil || d.Status != 403 || d.Message != "refusal" || !strings.Contains(out.String(), "partial") || strings.Contains(out.String(), "refusal") || strings.Contains(out.String(), "message_stop") {
			t.Fatalf("queued failure: err=%v out=%s", err, &out)
		}
	}
}

func TestNativeReaderPreservesBlocks(t *testing.T) {
	for _, data := range []string{`{"type":"content_block_delta","delta":{"text":"hello"}}`, "plain\ntext", "[\n1,\n2\n]", "{\"text\":\n\"hello\"}"} {
		for _, end := range []string{"\n\n", ""} {
			for _, newline := range []string{"\n", "\r\n"} {
				wire := "event: old\ndata: " + strings.ReplaceAll(data, "\n", "\ndata: ") + "\n: comment\nid: 7\nevent: new\nretry: 42" + end
				wire = strings.ReplaceAll(wire, "\n", newline)
				want := wire
				if !strings.HasSuffix(wire, "\n\n") {
					want += "\n\n"
				}
				var out bytes.Buffer
				if err := relayAnthropicStream(strings.NewReader(wire), &out); err != nil || out.String() != want {
					t.Fatalf("block changed: err=%v got=%q want=%q", err, out.String(), want)
				}
			}
		}
	}
	// The relay's splitter is LF-only: CRLF separators remain inside one block.
	wire := "data: {}\r\n\r\ndata: []\r\n\r\n"
	var out bytes.Buffer
	if err := relayAnthropicStream(strings.NewReader(wire), &out); err != nil || out.String() != wire+"\n\n" {
		t.Fatalf("CRLF split changed: err=%v out=%q", err, &out)
	}
	// A large joined event is bounded as one block, not at the former 1 MiB limit.
	wire = "data: [\n" + strings.Repeat("data:         1,\n", 100000) + "data:         1]\n\n"
	out.Reset()
	if err := relayAnthropicStream(strings.NewReader(wire), &out); err != nil || out.String() != wire {
		t.Fatalf("large joined event: err=%v bytes=%d", err, out.Len())
	}
}

func TestNativeReaderEventFieldRules(t *testing.T) {
	for _, wire := range []string{
		"event: error\ndata: broken\n\n", "event: response.failed\n\n",
		"event: error\ndata: {}\ndata: {}\n\n", "event: response.failed\ndata: {}\ndata: {}\n\n",
		"data: {\"error\":\ndata: {\"code\":NaN}}\n\n",
		"data: {\"error\":{", "data: {\"error\":\ndata: {}\ndata: [DONE]\n\n",
		"event: old\ndata: {}\nevent: error", // last name wins, also at EOF
	} {
		var out bytes.Buffer
		err := relayAnthropicStream(strings.NewReader(wire), &out)
		if err == nil || upstreamerror.Parse(err).Status != 502 || out.Len() != 0 {
			t.Fatalf("named/malformed error escaped: err=%v out=%q", err, &out)
		}
	}
	for _, wire := range []string{
		"event:error\ndata: {}\n\n", "event\ndata: {}\n\n",
		"data:{\"error\":{}}\n\n", "data\n\n",
		"event: error\nevent: ordinary\ndata: {}\n\n",
	} {
		var out bytes.Buffer
		if err := relayAnthropicStream(strings.NewReader(wire), &out); err != nil || out.String() != wire {
			t.Fatalf("field rule changed: err=%v out=%q", err, &out)
		}
	}
}

func TestResponsesReaderJoinedDataAndBounds(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		wire := "\n: comment\nid: 7\n\nevent: ignored\ndata: {\"type\":\"response.output_text.delta\",\n: keepalive\ndata: \"delta\":\"joined\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":2,\"total_tokens\":7}}}\n\n"
		var out bytes.Buffer
		err := translateOpenAIResponsesStream(strings.NewReader(strings.ReplaceAll(wire, "\n", newline)), &out)
		if err != nil || !strings.Contains(out.String(), "joined") || !strings.Contains(out.String(), "message_stop") {
			t.Fatalf("joined response: err=%v out=%s", err, &out)
		}
	}
	for _, wire := range []string{"data: " + strings.Repeat("x", 1<<20) + "\n\n", strings.Repeat("data: "+strings.Repeat("x", 1000)+"\n", 1100) + "\n"} {
		if err := translateOpenAIResponsesStream(strings.NewReader(wire), io.Discard); err == nil {
			t.Fatal("oversized Responses event accepted")
		}
	}
	if err := translateOpenAIStreamToAnthropic(strings.NewReader("data: "+strings.Repeat("x", 1<<20)+"\n"), io.Discard); err == nil {
		t.Fatal("oversized OpenAI line accepted")
	}
}

type readerContractFailure struct{}

func (readerContractFailure) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type readerContractWriterFailure struct{}

func (readerContractWriterFailure) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestProviderReadersPropagateIOErrors(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		translate     func(io.Reader, io.Writer) error
	}{
		{"openai", "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n", translateOpenAIStreamToAnthropic},
		{"responses", "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n", translateOpenAIResponsesStream},
		{"native", "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"partial\"}}\n\n", relayAnthropicStream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := tc.translate(io.MultiReader(strings.NewReader(tc.content+"data: {"), readerContractFailure{}), &out)
			if !errors.Is(err, io.ErrUnexpectedEOF) || !strings.Contains(out.String(), "partial") {
				t.Fatalf("read error lost: err=%v out=%s", err, &out)
			}
			if err := tc.translate(strings.NewReader(tc.content), readerContractWriterFailure{}); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("write error lost: %v", err)
			}
		})
	}
}

func TestOpenAINestedErrorsBeforeTypedDecode(t *testing.T) {
	for _, location := range []string{"choice", "delta"} {
		choice := `{"error":{"code":403,"message":"refused"}}`
		if location == "delta" {
			choice = `{"delta":` + choice + `}`
		}
		payload := `{"choices":[` + choice + `],"usage":{"prompt_tokens":` + strings.Repeat("9", 400) + `}}`
		for _, provider := range []string{"openai", "privatemode", "tencent"} {
			err := translateOpenAIStreamToAnthropicForProvider(strings.NewReader("data: "+payload+"\n"), io.Discard, provider)
			d := upstreamerror.Parse(err)
			want, message := 403, "refused"
			if provider == "tencent" {
				want, message = 502, "Tencent TokenHub stream failed"
			}
			if err == nil || d.Status != want || d.Message != message {
				t.Fatalf("%s/%s: nested error lost: %+v", provider, location, d)
			}
		}
	}
}

func TestResponsesErrorTextIsClientOnly(t *testing.T) {
	const payload = `{"type":"response.failed","response":{"error":{"code":403,"message":"ECHOED PRIVATE PROMPT"}}}`
	err := translateOpenAIResponsesStream(strings.NewReader("data: "+payload+"\n\n"), io.Discard)
	if err == nil || strings.Contains(err.Error(), "PRIVATE") || upstreamerror.Parse(err).Message != "ECHOED PRIVATE PROMPT" {
		t.Fatalf("error rendering: %v", err)
	}
}
