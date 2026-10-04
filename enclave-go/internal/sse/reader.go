// Package sse assembles bounded provider events before interpreting their data.
package sse

import (
	"bufio"
	"encoding/json"
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
	pending  []Event
	err      error
}

func NewReader(r io.Reader, maxBytes int) *Reader {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, min(64*1024, maxBytes)), maxBytes)
	return &Reader{scanner: scanner, maxBytes: maxBytes}
}

// Next collects all data fields through the blank line (or EOF). Comments and
// other fields never split an event. Providers that omit blank lines are also
// accepted when every data line is a complete JSON value or [DONE]. Raw retains
// native framing except when splitting such lines into separate relay events.
func (r *Reader) Next() bool {
	if r.err != nil {
		return false
	}
	if len(r.pending) > 0 {
		event := r.pending[0]
		r.pending[0] = Event{}
		r.pending = r.pending[1:]
		return r.emit(event)
	}
	var raw, data strings.Builder
	event := Event{}
	hasData := false
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
			if hasData {
				data.WriteByte('\n')
			}
			data.WriteString(value)
			hasData = true
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
	if lines := separateDataLines(event.Data); len(lines) > 0 {
		for _, line := range lines {
			part := event
			part.Data = line
			part.Raw = "" // Frame on delivery, without copying the name per queued line.
			r.pending = append(r.pending, part)
		}
		return r.Next()
	}
	return r.emit(event)
}

// Prefer the assembled JSON payload. Only unambiguously complete individual
// lines qualify for the legacy framing fallback; malformed data stays joined.
func separateDataLines(data string) []string {
	if !strings.Contains(data, "\n") || json.Valid([]byte(data)) {
		return nil
	}
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "[DONE]" && !json.Valid([]byte(line)) {
			return nil
		}
	}
	return lines
}

func (r *Reader) emit(event Event) bool {
	// Check on delivery so earlier content is visible before a queued failure.
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
