package sse

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestReaderAssemblesEvents(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		for _, end := range []string{"\n\n", ""} {
			wire := "event: chunk\ndata: {\"text\":\n: keepalive\nid: 7\ndata: \"hello\"}" + end
			r := NewReader(strings.NewReader(strings.ReplaceAll(wire, "\n", newline)), 1024)
			if !r.Next() || r.Event().Name != "chunk" || r.Event().Data != "{\"text\":\n\"hello\"}" {
				t.Fatalf("event=%+v err=%v", r.Event(), r.Err())
			}
			if r.Next() || r.Err() != nil {
				t.Fatalf("extra event or error: %v", r.Err())
			}
		}
	}
}

func TestReaderSupportsBothEventFramings(t *testing.T) {
	want := []string{`{"text":"first"}`, `{"text":"second"}`, `{"usage":{"tokens":2}}`}
	for _, framing := range []struct{ name, separator string }{
		{"blank-line", "\n\n"},
		{"single-newline", "\n"},
	} {
		for _, ending := range []struct{ name, wire string }{
			{"blank-line", "\n\n"}, {"newline", "\n"}, {"eof", ""},
		} {
			for _, newline := range []struct{ name, wire string }{{"lf", "\n"}, {"crlf", "\r\n"}} {
				t.Run(framing.name+"/"+ending.name+"/"+newline.name, func(t *testing.T) {
					wire := "data: " + strings.Join(want, framing.separator+"data: ") + ending.wire
					r := NewReader(strings.NewReader(strings.ReplaceAll(wire, "\n", newline.wire)), 1024)
					for i, data := range want {
						if !r.Next() || r.Event().Data != data {
							t.Fatalf("event %d: got=%+v want=%q err=%v", i, r.Event(), data, r.Err())
						}
						// Relays must receive only this event, never later queued content.
						relay := NewReader(strings.NewReader(r.Event().Raw), 1024)
						if !relay.Next() || relay.Event().Data != data || relay.Next() || relay.Err() != nil {
							t.Fatalf("invalid relay event: %q err=%v", r.Event().Raw, relay.Err())
						}
					}
					if r.Next() || r.Err() != nil {
						t.Fatalf("extra event or error: %+v err=%v", r.Event(), r.Err())
					}
				})
			}
		}
	}
}

func TestReaderChecksEachQueuedEvent(t *testing.T) {
	const content = `{"text":"partial"}`
	const failure = `{"error":{"code":403,"message":"refusal"}}`
	for _, ending := range []string{"\n\n", "\n", ""} {
		r := NewReader(strings.NewReader("data: "+content+"\ndata: "+failure+"\ndata: [DONE]"+ending), 1024)
		if !r.Next() || r.Event().Data != content || strings.Contains(r.Event().Raw, "refusal") || r.Err() != nil {
			t.Fatalf("content lost or error relayed: %+v err=%v", r.Event(), r.Err())
		}
		if r.Next() || r.Err() == nil {
			t.Fatalf("queued failure lost: %+v err=%v", r.Event(), r.Err())
		}
		detail := upstreamerror.Parse(r.Err())
		if detail.Status != 403 || detail.Message != "refusal" || detail.Raw != failure {
			t.Fatalf("wrong failure: %+v", detail)
		}
		if r.Next() {
			t.Fatal("emitted [DONE] after failure")
		}
	}
}

func TestReaderJoinsSplitJSONError(t *testing.T) {
	const first = `{"type":"error",`
	const second = `"error":{"code":403,"message":"multiline refusal"}}`
	for _, name := range []string{"", "event: error\n"} {
		for _, ending := range []string{"\n\n", ""} {
			wire := name + "data: " + first + "\n: keepalive\ndata: " + second + ending
			r := NewReader(strings.NewReader(wire), 1024)
			if r.Next() || r.Err() == nil {
				t.Fatalf("split failure lost: %q err=%v", wire, r.Err())
			}
			detail := upstreamerror.Parse(r.Err())
			if detail.Status != 403 || detail.Message != "multiline refusal" || detail.Raw != first+"\n"+second {
				t.Fatalf("wrong split failure: %+v", detail)
			}
		}
	}
}

func TestReaderDoneFraming(t *testing.T) {
	for _, wire := range []string{
		"data: [DONE]",
		"data: [DONE]\n\n",
		"data: {}\ndata: [DONE]",
		"data: {}\ndata: [DONE]\n\n",
		"data: {}\n\ndata: [DONE]\n\n",
	} {
		r := NewReader(strings.NewReader(wire), 1024)
		if strings.Contains(wire, "{}") {
			if !r.Next() || r.Event().Data != "{}" {
				t.Fatalf("lost content before [DONE]: %q err=%v", wire, r.Err())
			}
		}
		if !r.Next() || r.Event().Data != "[DONE]" {
			t.Fatalf("lost [DONE]: %q event=%+v err=%v", wire, r.Event(), r.Err())
		}
		if r.Next() || r.Err() != nil {
			t.Fatalf("extra event or error after [DONE]: %q err=%v", wire, r.Err())
		}
	}
}

func TestReaderDrainsQueueBeforeReadingNextEvent(t *testing.T) {
	r := NewReader(strings.NewReader("data: 1\ndata: 2\n\ndata: 3\ndata: 4\n\n"), 1024)
	for _, want := range []string{"1", "2", "3", "4"} {
		if !r.Next() || r.Event().Data != want {
			t.Fatalf("event=%+v want=%q err=%v", r.Event(), want, r.Err())
		}
	}
	if r.Next() || r.Err() != nil {
		t.Fatalf("extra event or error: %v", r.Err())
	}
}

func TestReaderPreservesSplitEventMetadata(t *testing.T) {
	r := NewReader(strings.NewReader("event: chunk\nid: 7\ndata: {}\n: keepalive\ndata: []\n\n"), 1024)
	for _, data := range []string{"{}", "[]"} {
		if !r.Next() || r.Event().Name != "chunk" || r.Event().Data != data || !r.Event().UnexpectedField {
			t.Fatalf("metadata lost: %+v err=%v", r.Event(), r.Err())
		}
		if r.Event().Raw != "event: chunk\ndata: "+data+"\n\n" {
			t.Fatalf("incorrect relay framing: %q", r.Event().Raw)
		}
	}
	if r.Next() || r.Err() != nil {
		t.Fatalf("extra event or error: %v", r.Err())
	}
}

func TestReaderKeepsOtherMultilineDataJoined(t *testing.T) {
	for _, data := range []string{"plain\ntext", "[DONE]\nnot JSON", "1\n", "[\n1,\n2\n]"} {
		wire := "data: " + strings.ReplaceAll(data, "\n", "\ndata: ") + "\n\n"
		r := NewReader(strings.NewReader(wire), 1024)
		if !r.Next() || r.Event().Data != data || r.Event().Raw != wire {
			t.Fatalf("event changed: got=%+v want=%q err=%v", r.Event(), data, r.Err())
		}
		if r.Next() || r.Err() != nil {
			t.Fatalf("extra event or error: %v", r.Err())
		}
	}
}

func TestReaderFailsClosed(t *testing.T) {
	for _, wire := range []string{
		"event: error\ndata: broken\n\n",
		"event: response.failed\n\n",
		"data: {\"error\":\ndata: {\"code\":NaN}}\n\n",
		"data: {\"error\":",
		"data: {}\ndata: {\"error\":\n\n",
		"data: {\"error\":\ndata: {}\ndata: [DONE]\n\n",
		"data: {}\ndata: not JSON\n\n",
		"event: error\ndata: {}\ndata: {}\n\n",
		"event: response.failed\ndata: {}\ndata: {}\n\n",
	} {
		r := NewReader(strings.NewReader(wire), 1024)
		if r.Next() || r.Err() == nil || upstreamerror.Parse(r.Err()).Status != 502 {
			t.Fatalf("failure lost: %q err=%v", wire, r.Err())
		}
	}
}

func TestReaderBoundsWholeEvent(t *testing.T) {
	for _, data := range []string{"x", "{}"} {
		r := NewReader(strings.NewReader(strings.Repeat("data: "+data+"\n", 50)+"\n"), 128)
		if r.Next() || !errors.Is(r.Err(), io.ErrShortBuffer) {
			t.Fatalf("oversized event accepted: %v", r.Err())
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestReaderPropagatesReadError(t *testing.T) {
	r := NewReader(io.MultiReader(strings.NewReader("data: {}\n\ndata: {"), failingReader{}), 1024)
	if !r.Next() {
		t.Fatalf("lost complete event: %v", r.Err())
	}
	if r.Next() || !errors.Is(r.Err(), io.ErrUnexpectedEOF) {
		t.Fatalf("read failure lost: %v", r.Err())
	}
}
