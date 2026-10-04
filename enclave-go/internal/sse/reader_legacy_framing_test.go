package sse

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestReaderSingleNewlineStreamsBeforeEOF(t *testing.T) {
	pr, pw := io.Pipe()
	r := NewReader(pr, 1024)
	done := make(chan bool, 1)
	go func() { done <- r.Next() }()
	t.Cleanup(func() { pr.Close(); pw.Close() })
	// Supply only the current data line and its boundary lookahead. Reading
	// any further blocks: neither a blank line nor EOF is available.
	if _, err := io.WriteString(pw, "data: {\"text\":\"first\"}\ndata: {\"text\":\"second\"}\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-done:
		if !ok || r.Event().Data != `{"text":"first"}` || r.Event().Raw != "data: {\"text\":\"first\"}\n\n" {
			t.Fatalf("event=%+v err=%v", r.Event(), r.Err())
		}
	case <-time.After(time.Second):
		pr.Close()
		<-done
		t.Fatal("first event buffered while waiting for more lines or EOF")
	}
}

func TestReaderSingleNewlineLongStream(t *testing.T) {
	const count = 15000
	chunk := func(i int) string {
		return fmt.Sprintf(`{"choices":[{"index":%d,"delta":{"content":"a content chunk long enough to exceed the stream size bound"}}]}`, i)
	}
	var wire strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&wire, "data: %s\n", chunk(i))
	}
	if wire.Len() <= 1<<20 {
		t.Fatal("fixture must exceed 1 MiB")
	}
	r := NewReader(strings.NewReader(wire.String()), 1<<20)
	for i := 0; i < count; i++ {
		if !r.Next() || r.Event().Data != chunk(i) {
			t.Fatalf("event %d: got=%+v err=%v", i, r.Event(), r.Err())
		}
	}
	if r.Next() || r.Err() != nil {
		t.Fatalf("extra event or error: %v", r.Err())
	}
}

func TestReaderSingleNewlineNames(t *testing.T) {
	const first = "event: content_block_delta\ndata: {\"delta\":{\"text\":\"hello\"}}\n"
	const second = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n"
	r := NewReader(strings.NewReader(first+second+"\n"), 1024)
	for i, want := range []Event{
		{Name: "content_block_delta", Data: `{"delta":{"text":"hello"}}`, Raw: first + "\n"},
		{Name: "message_stop", Data: `{"type":"message_stop"}`, Raw: second + "\n"},
	} {
		if !r.Next() || r.Event() != want {
			t.Fatalf("event %d: got=%+v want=%+v err=%v", i, r.Event(), want, r.Err())
		}
	}
	if r.Next() || r.Err() != nil {
		t.Fatalf("extra event or error: %v", r.Err())
	}
}

func TestReaderLineBoundariesPreserveFramingAndErrors(t *testing.T) {
	t.Run("native raw", func(t *testing.T) {
		const wire = ": before\nevent: chunk\nid: 7\ndata:  {\"text\":\"hi\"} \n: after\nretry: 42\n\n"
		r := NewReader(strings.NewReader(wire), 1024)
		if !r.Next() || r.Event().Raw != wire || r.Event().Name != "chunk" || !r.Event().UnexpectedField || r.Next() || r.Err() != nil {
			t.Fatalf("native framing changed: %+v err=%v", r.Event(), r.Err())
		}
	})
	t.Run("content then split error", func(t *testing.T) {
		const failure = "{\"error\":\n{\"message\":\"refused\",\"code\":403}}"
		r := NewReader(strings.NewReader("data: {}\ndata: {\"error\":\n: comment\nid: 7\ndata: {\"message\":\"refused\",\"code\":403}}\ndata: [DONE]\n"), 1024)
		if !r.Next() || r.Event().Data != "{}" || r.Err() != nil {
			t.Fatalf("lost content: %+v err=%v", r.Event(), r.Err())
		}
		if r.Next() || r.Err() == nil {
			t.Fatal("lost multiline error after content")
		}
		if d := upstreamerror.Parse(r.Err()); d.Status != 502 || d.Message != "refused" || d.Raw != failure+"\n[DONE]" {
			t.Fatalf("wrong error: %+v", d)
		}
		if r.Next() {
			t.Fatal("delivered DONE after error")
		}
	})
	t.Run("done boundary", func(t *testing.T) {
		r := NewReader(strings.NewReader("data: {}\ndata:  [DONE] \ndata: {}\n\n"), 1024)
		for _, want := range []string{"{}", " [DONE] ", "{}"} {
			if !r.Next() || r.Event().Data != want {
				t.Fatalf("event=%+v want=%q err=%v", r.Event(), want, r.Err())
			}
		}
		if r.Next() || r.Err() != nil {
			t.Fatalf("extra event or error: %v", r.Err())
		}
	})
}
