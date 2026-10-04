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
	scanner      *bufio.Scanner
	maxBytes     int
	event        Event
	pendingLine  string
	pendingEvent Event
	err          error
}

func NewReader(r io.Reader, maxBytes int) *Reader {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, min(64*1024, maxBytes)), maxBytes)
	return &Reader{scanner: scanner, maxBytes: maxBytes}
}

var dataComplete = func(data string) bool {
	return strings.TrimSpace(data) == "[DONE]" || json.Valid([]byte(data))
}

// Next collects data through a blank line or EOF. A single data line holding a
// complete JSON value or [DONE] also ends at the next data field or named-event
// boundary, tolerating providers that omit blank lines. Multiline data stays
// joined. Comments and other fields never split an event. Raw retains native
// framing except for these legacy split events.
func (r *Reader) Next() bool {
	if r.err != nil {
		return false
	}
	var raw, data strings.Builder
	event := r.pendingEvent
	r.pendingEvent = Event{}
	inheritedMetadata := event != (Event{})
	dataLines := 0
	singleDataComplete := false
	complete := false
	for {
		line := r.pendingLine
		r.pendingLine = ""
		if line == "" {
			if !r.scanner.Scan() {
				break
			}
			line = r.scanner.Text()
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		if dataLines == 1 && singleDataComplete && (field == "data" || field == "event" && event.Name != "") {
			r.pendingLine = line
			if field == "data" {
				// Keep metadata shared by legacy data lines until a new event
				// name or a blank line, as in the original tolerant split.
				r.pendingEvent = Event{Name: event.Name, UnexpectedField: event.UnexpectedField}
			}
			event.Data = data.String()
			return r.emit(event)
		}
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
		switch field {
		case "data":
			if dataLines > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(value)
			dataLines++
			if dataLines == 1 {
				// Only single-line events qualify for legacy splitting. Cache
				// completeness so repeated event fields cannot rescan this line.
				singleDataComplete = dataComplete(value)
			}
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
	if inheritedMetadata {
		event.Raw = "" // Include inherited metadata in the last legacy part too.
	}
	return r.emit(event)
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
