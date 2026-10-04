// Package sse assembles bounded provider events before interpreting their data.
package sse

import (
	"bufio"
	"io"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

type Event struct {
	Name, Data, Raw string
	UnexpectedField bool
}

type Reader struct {
	scanner  *bufio.Scanner
	maxBytes int
	event    Event
	err      error
	byLine   bool
	name     string
}

// NewReader uses spec framing: only a blank line or EOF ends an event.
// Raw is LF-normalized by bufio.Scanner, including CRLF upstream streams.
func NewReader(r io.Reader, maxBytes int) *Reader {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, min(64*1024, maxBytes)), maxBytes)
	return &Reader{scanner: scanner, maxBytes: maxBytes}
}

// NewLineReader delivers each data line immediately, matching the original
// OpenAI-compatible, Gemini and encrypted Chutes readers. maxBytes bounds a
// line, rather than a whole event. Blank lines reset the event name.
// A split error report fails closed on the first error-looking fragment:
// these paths refund with a generic 502, without parsing the provider status.
// Spec-framed paths use NewReader and parse the joined report instead.
func NewLineReader(r io.Reader, maxBytes int) *Reader {
	reader := NewReader(r, maxBytes)
	reader.byLine = true
	return reader
}

func (r *Reader) Next() bool {
	if r.err != nil {
		return false
	}
	if r.byLine {
		return r.nextLine()
	}
	var raw, data strings.Builder
	var event Event
	dataLines := 0
	complete := false
	for r.scanner.Scan() {
		line := r.scanner.Text()
		if raw.Len()+len(line)+1 > r.maxBytes {
			r.err = io.ErrShortBuffer
			return false
		}
		raw.WriteString(line)
		raw.WriteByte('\n')
		if line == "" {
			complete = true
			break
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "data":
			if dataLines > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(value)
			dataLines++
		case "event":
			event.Name = value
		case "": // comment
		default:
			event.UnexpectedField = true
		}
	}
	if err := r.scanner.Err(); !complete && err != nil {
		r.err = err
		return false
	}
	if raw.Len() == 0 {
		return false
	}
	event.Data, event.Raw = data.String(), raw.String()
	return r.emit(event)
}

func (r *Reader) nextLine() bool {
	for r.scanner.Scan() {
		line := r.scanner.Text()
		if line == "" {
			r.name = ""
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			r.name = value
		case "data":
			return r.emit(Event{Name: r.name, Data: value})
		case "": // comment
		default:
			// An empty event lets strict callers (encrypted Chutes) reject
			// unknown fields as main did; other readers skip empty data.
			return r.emit(Event{UnexpectedField: true})
		}
	}
	r.err = r.scanner.Err()
	return false
}

func (r *Reader) emit(event Event) bool {
	// Check on delivery so earlier content is visible before a later failure.
	if err := CheckError(event.Name, event.Data); err != nil {
		r.err = err
		return false
	}
	if event.Raw == "" {
		event.Raw = "data: " + event.Data + "\n\n"
		if event.Name != "" {
			event.Raw = "event: " + event.Name + "\n" + event.Raw
		}
	}
	r.event = event
	return true
}

func (r *Reader) Event() Event { return r.event }
func (r *Reader) Err() error   { return r.err }

// CheckError also applies to providers such as Bedrock whose transport already
// supplies a complete JSON event, and to failures declared by the SSE name.
func CheckError(name, data string) error {
	if err := upstreamerror.FromEvent(data); err != nil {
		return err
	}
	if name == "error" || name == "response.failed" {
		return &upstreamerror.Error{Status: 502, Body: data}
	}
	return nil
}
