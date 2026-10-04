package sse

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type deliveryBarrier struct {
	io.Reader
	reads     int
	delivered *bool
}

func (r *deliveryBarrier) Read(p []byte) (int, error) {
	if r.reads > 0 && !*r.delivered {
		return 0, errors.New("read ahead before delivering the first event")
	}
	r.reads++
	return r.Reader.Read(p)
}

func TestReaderDelivery(t *testing.T) {
	for _, spec := range []bool{false, true} {
		t.Run(map[bool]string{false: "line", true: "spec"}[spec], func(t *testing.T) {
			pr, pw := io.Pipe()
			defer pr.Close()
			defer pw.Close()
			advance := make(chan struct{})
			defer close(advance)
			separator := "\n"
			if spec {
				separator = "\n\n"
			}
			go func() {
				defer pw.Close()
				io.WriteString(pw, "data: {}"+separator)
				<-advance // Event 2 is not written until event 1 has been delivered.
				io.WriteString(pw, "data: []"+separator)
			}()
			delivered := false
			input := &deliveryBarrier{Reader: pr, delivered: &delivered}
			r := NewLineReader(input, 1024)
			if spec {
				r = NewReader(input, 1024)
			}
			if !r.Next() || r.Event().Data != "{}" {
				t.Fatalf("first event=%+v err=%v", r.Event(), r.Err())
			}
			delivered = true
			advance <- struct{}{}
			if !r.Next() || r.Event().Data != "[]" || r.Next() || r.Err() != nil {
				t.Fatalf("second event=%+v err=%v", r.Event(), r.Err())
			}
		})
	}
}

func TestSpecLastNameAndJoinedData(t *testing.T) {
	for _, data := range []string{"data: {}", "data: {}\ndata: []"} {
		for _, end := range []string{"\n\n", ""} {
			wire := "event: old\n" + data + "\n: comment\nid: 7\nevent: new" + end
			r := NewReader(strings.NewReader(wire), 1024)
			want := strings.TrimPrefix(strings.ReplaceAll(data, "\ndata: ", "\n"), "data: ")
			if !r.Next() || r.Event().Name != "new" || r.Event().Data != want {
				t.Fatalf("event=%+v err=%v", r.Event(), r.Err())
			}
			if r.Next() || r.Err() != nil {
				t.Fatalf("extra event: %+v err=%v", r.Event(), r.Err())
			}
		}
	}
}

func TestLineMetadataAndBounds(t *testing.T) {
	wire := "event: old\nid: flagged\ndata: {}\n: comment\nevent: new\ndata: []\n\ndata: not JSON\n"
	r := NewLineReader(strings.NewReader(wire), 128)
	// An unknown field arrives as an empty, unnamed marker event, so strict
	// callers can reject it and every other reader skips its empty data.
	if !r.Next() || !r.Event().UnexpectedField || r.Event().Data != "" || r.Event().Name != "" {
		t.Fatalf("unknown field not flagged: %+v err=%v", r.Event(), r.Err())
	}
	for _, want := range []Event{
		{Name: "old", Data: "{}", Raw: "event: old\ndata: {}\n\n"},
		{Name: "new", Data: "[]", Raw: "event: new\ndata: []\n\n"},
		{Data: "not JSON", Raw: "data: not JSON\n\n"},
	} {
		if !r.Next() || r.Event() != want {
			t.Fatalf("got=%+v want=%+v err=%v", r.Event(), want, r.Err())
		}
	}
	if r.Next() || r.Err() != nil {
		t.Fatalf("unexpected event/error: %v", r.Err())
	}
	r = NewLineReader(strings.NewReader(strings.Repeat("data: x\n", 100)), 16)
	for i := 0; i < 100; i++ {
		if !r.Next() {
			t.Fatalf("bounded the stream instead of a line: %v", r.Err())
		}
	}
	r = NewLineReader(strings.NewReader("data: "+strings.Repeat("x", 128)+"\n"), 128)
	if r.Next() || r.Err() == nil {
		t.Fatal("oversized line accepted")
	}
}

func TestSpecRawNormalizationAndLargeEvent(t *testing.T) {
	const raw = ": before\nevent: chunk\nid: 7\ndata: {}\n: after\nretry: 42\n\n"
	for _, newline := range []string{"\n", "\r\n"} {
		r := NewReader(strings.NewReader(strings.ReplaceAll(raw, "\n", newline)), 1024)
		if !r.Next() || r.Event().Raw != raw || r.Event().Name != "chunk" || !r.Event().UnexpectedField || r.Next() || r.Err() != nil {
			t.Fatalf("raw event changed: %+v err=%v", r.Event(), r.Err())
		}
	}
	data := "[\n" + strings.Repeat("        1,\n", 100000) + "        1]"
	wire := "data: " + strings.ReplaceAll(data, "\n", "\ndata: ") + "\n\n"
	r := NewReader(strings.NewReader(wire), 2<<20)
	if !r.Next() || r.Event().Data != data || r.Event().Raw != wire || r.Next() || r.Err() != nil {
		t.Fatalf("large joined event failed: %v", r.Err())
	}
}
