package deidentify

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

var tokenPattern = regexp.MustCompile(`\[TR[A-Z]{16}_[A-Z_]+_[0-9]+\]`)

func validToken(s string) bool { return len(s) <= 128 && tokenPattern.FindString(s) == s }

// Session is private to one request and never serialized or cached.
type Session struct{ replacements map[string]string }

func (s *Session) reveal(text string, escaped bool) string {
	return tokenPattern.ReplaceAllStringFunc(text, func(token string) string {
		value, ok := s.replacements[token]
		if !ok {
			return token
		}
		if escaped {
			b, _ := json.Marshal(value)
			return string(b[1 : len(b)-1])
		}
		return value
	})
}

func (s *Session) revealJSON(value any) any {
	switch v := value.(type) {
	case string:
		return s.reveal(v, false)
	case []any:
		for i, x := range v {
			v[i] = s.revealJSON(x)
		}
	case map[string]any:
		for k, x := range v {
			v[k] = s.revealJSON(x)
		}
	}
	return value
}

func (s *Session) withinBudget(value any, budget *int) bool {
	switch v := value.(type) {
	case string:
		*budget -= len(v)
		for _, token := range tokenPattern.FindAllString(v, -1) {
			if raw, ok := s.replacements[token]; ok {
				*budget -= 6 * len(raw)
			}
		}
	case []any:
		for _, child := range v {
			if !s.withinBudget(child, budget) {
				return false
			}
		}
	case map[string]any:
		for key, child := range v {
			*budget -= len(key)
			if !s.withinBudget(child, budget) {
				return false
			}
		}
	}
	return *budget >= 0
}

type pendingDelta struct {
	tail  string
	field string
	event map[string]any
}
type StreamWriter struct {
	out     io.Writer
	session *Session
	buffer  []byte
	pending map[json.Number]*pendingDelta
	err     error
}

// Writer restores the normalized provider SSE before the public adapters hash
// and sign output. It never edits usage, routing, signatures or protocol IDs.
func (s *Session) Writer(out io.Writer) *StreamWriter {
	return &StreamWriter{out: out, session: s, pending: make(map[json.Number]*pendingDelta)}
}

func (w *StreamWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	for _, b := range data {
		w.buffer = append(w.buffer, b)
		if len(w.buffer) > 1<<20 {
			w.err = ErrUnavailable
			return 0, w.err
		}
		if bytes.HasSuffix(w.buffer, []byte("\n\n")) || bytes.HasSuffix(w.buffer, []byte("\r\n\r\n")) {
			if err := w.frame(w.buffer); err != nil {
				w.err = err
				return 0, err
			}
			w.buffer = w.buffer[:0]
		}
	}
	return len(data), nil
}

func (w *StreamWriter) Close() error {
	if w.err != nil {
		return w.err
	}
	if len(bytes.TrimSpace(w.buffer)) != 0 || len(w.pending) != 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (w *StreamWriter) emit(event map[string]any) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	kind, _ := event["type"].(string)
	_, err = io.WriteString(w.out, "event: "+kind+"\ndata: "+string(data)+"\n\n")
	return err
}

func (w *StreamWriter) frame(frame []byte) error {
	var payload []string
	for _, line := range strings.Split(strings.ReplaceAll(string(frame), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "data:") {
			payload = append(payload, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if len(payload) == 0 {
		_, err := w.out.Write(frame)
		return err
	}
	raw := strings.Join(payload, "\n")
	var event map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if !json.Valid([]byte(raw)) || decoder.Decode(&event) != nil || event == nil {
		return ErrUnavailable
	}
	index, _ := event["index"].(json.Number)
	if oneOf(event["type"], "content_block_start", "content_block_delta", "content_block_stop") {
		n, err := index.Int64()
		if err != nil || n < 0 {
			return ErrUnavailable
		}
	}
	switch event["type"] {
	case "content_block_start":
		if _, exists := w.pending[index]; exists {
			return ErrUnavailable
		}
		block, _ := event["content_block"].(map[string]any)
		budget := 1 << 20
		if !w.session.withinBudget(block, &budget) {
			return ErrUnavailable
		}
		for _, field := range []string{"text", "thinking", "input"} {
			if v, ok := block[field]; ok {
				if text, ok := v.(string); ok && field != "input" {
					head, tail := splitTokenTail(text)
					block[field] = w.session.reveal(head, false)
					if tail != "" {
						deltaEvent := map[string]any{"type": "content_block_delta", "index": index, "delta": map[string]any{"type": field + "_delta", field: ""}}
						w.pending[index] = &pendingDelta{tail: tail, field: field, event: deltaEvent}
					}
				} else {
					block[field] = w.session.revealJSON(v)
				}
			}
		}
	case "content_block_delta":
		delta, _ := event["delta"].(map[string]any)
		field := ""
		switch delta["type"] {
		case "text_delta":
			field = "text"
		case "thinking_delta":
			field = "thinking"
		case "input_json_delta":
			field = "partial_json"
		}
		if field != "" {
			text, ok := delta[field].(string)
			if !ok {
				return ErrUnavailable
			}
			prior := w.pending[index]
			if prior != nil && prior.field != field {
				return ErrUnavailable
			}
			if prior != nil {
				text = prior.tail + text
			}
			head, tail := splitTokenTail(text)
			budget := 1 << 20
			if !w.session.withinBudget(head, &budget) {
				return ErrUnavailable
			}
			delta[field] = w.session.reveal(head, field == "partial_json")
			w.pending[index] = &pendingDelta{tail: tail, field: field, event: event}
		}
	case "content_block_stop":
		if p := w.pending[index]; p != nil {
			if p.tail != "" {
				delta := p.event["delta"].(map[string]any)
				delta[p.field] = p.tail
				if err := w.emit(p.event); err != nil {
					return err
				}
			}
			delete(w.pending, index)
		}
	}
	return w.emit(event)
}

// Keep only a possible placeholder prefix, not an entire response or stream.
func splitTokenTail(text string) (string, string) {
	at := strings.LastIndexByte(text, '[')
	if at < 0 {
		return text, ""
	}
	tail := text[at:]
	if len(tail) > 128 || strings.Contains(tail, "]") {
		return text, ""
	}
	for _, r := range tail[1:] {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return text, ""
		}
	}
	return text[:at], tail
}
