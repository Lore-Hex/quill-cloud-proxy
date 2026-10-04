package sse

import (
	"errors"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestReaderMultilineValidationIsLinear(t *testing.T) {
	// Short, pretty-printed lines keep every prefix syntactically valid but
	// incomplete until the final line. The payload is about 1 MiB, and its
	// SSE framing also fits within the 2 MiB event limit.
	data := "[\n" + strings.Repeat("        1,\n", 100000) + "        1]"
	wire := "data: " + strings.ReplaceAll(data, "\n", "\ndata: ") + "\n\n"
	var inspected int64
	original := dataComplete
	dataComplete = func(data string) bool {
		inspected += int64(len(data))
		return original(data)
	}
	t.Cleanup(func() { dataComplete = original })

	r := NewReader(strings.NewReader(wire), 2<<20)
	if !r.Next() {
		t.Fatalf("missing multiline event: %v", r.Err())
	}
	if r.Event().Data != data || r.Event().Raw != wire {
		t.Fatal("multiline event was split or changed")
	}
	if r.Next() || r.Err() != nil {
		t.Fatalf("extra event or error: %v", r.Err())
	}
	limit := 2 * int64(len(data))
	t.Logf("data bytes=%d, wire bytes=%d, inspected bytes=%d, limit=%d", len(data), len(wire), inspected, limit)
	if inspected >= limit {
		t.Fatalf("completeness checks inspected %d bytes; want less than %d", inspected, limit)
	}
}

func TestReaderMultilineDataKeepsSpecFraming(t *testing.T) {
	for _, boundary := range []struct{ name, wire string }{
		{"data", ""},
		{"named event", "event: next\n"},
	} {
		for _, ending := range []struct{ name, wire string }{
			{"blank line", "\n\n"},
			{"EOF", ""},
		} {
			t.Run(boundary.name+"/"+ending.name, func(t *testing.T) {
				wire := "event: chunk\ndata: [\ndata: 1]\n" + boundary.wire + "data: {}" + ending.wire
				wantRaw := wire
				if ending.wire == "" {
					wantRaw += "\n"
				}
				r := NewReader(strings.NewReader(wire), 1024)
				if !r.Next() || r.Event().Data != "[\n1]\n{}" || r.Event().Raw != wantRaw {
					t.Fatalf("multiline data was split or changed: event=%+v err=%v", r.Event(), r.Err())
				}
				if r.Next() || r.Err() != nil {
					t.Fatalf("extra event or error: %v", r.Err())
				}
			})
		}
	}
}

func TestReaderMultilineErrorWithTrailingDataFailsClosed(t *testing.T) {
	const failure = "{\"error\":\n{\"message\":\"refused\",\"code\":403}}"
	for _, ending := range []struct{ name, wire string }{
		{"blank line", "\n\n"},
		{"EOF", ""},
	} {
		t.Run(ending.name, func(t *testing.T) {
			data := failure + "\n{}\n[DONE]"
			wire := "data: {}\ndata: " + strings.ReplaceAll(data, "\n", "\ndata: ") + ending.wire
			r := NewReader(strings.NewReader(wire), 1024)
			if !r.Next() || r.Event().Data != "{}" || r.Err() != nil {
				t.Fatalf("lost content before failure: event=%+v err=%v", r.Event(), r.Err())
			}
			if r.Next() {
				t.Fatal("delivered multiline error with trailing data")
			}
			var failure *upstreamerror.Error
			if !errors.As(r.Err(), &failure) || failure.Status != 502 || failure.Body != data {
				t.Fatalf("trailing-data failure lost: %v", r.Err())
			}
			if r.Next() {
				t.Fatal("delivered data after failure")
			}
		})
	}
}
