package main

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// sseBatchWriter coalesces only the narrow OpenAI chat.completion.chunk shape
// that is safe to merge: a single choice whose delta contains only string
// content, with no finish_reason, logprobs, or usage. Everything else flushes
// any pending content chunk and is written through byte-for-byte, so malformed
// frames and non-chat SSE fail open rather than being rewritten or dropped.
type sseBatchWriter struct {
	w        io.Writer
	interval time.Duration
	maxBytes int

	mu               sync.Mutex
	pendingInput     []byte
	bufferedRaw      []byte
	bufferedEvent    map[string]any
	bufferedChoice   map[string]any
	bufferedDelta    map[string]any
	bufferedContent  int
	timer            *time.Timer
	err              error
	firstContentSent bool
	closed           bool
}

func newSSEBatchWriter(w io.Writer) io.WriteCloser {
	ms := envInt("TR_SSE_BATCH_MS", 40)
	if ms <= 0 {
		return nopWriteCloser{w: w}
	}
	maxBytes := envInt("TR_SSE_BATCH_MAX_BYTES", 4096)
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	return &sseBatchWriter{
		w:        w,
		interval: time.Duration(ms) * time.Millisecond,
		maxBytes: maxBytes,
	}
}

type nopWriteCloser struct {
	w io.Writer
}

func (n nopWriteCloser) Write(p []byte) (int, error) {
	return n.w.Write(p)
}

func (n nopWriteCloser) Close() error {
	return nil
}

func (w *sseBatchWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if w.err != nil {
		return 0, w.err
	}
	w.pendingInput = append(w.pendingInput, p...)
	for {
		event, rest, ok := nextSSEEvent(w.pendingInput)
		if !ok {
			break
		}
		w.pendingInput = rest
		if err := w.handleEventLocked(event); err != nil {
			w.err = err
			return 0, err
		}
	}
	return len(p), nil
}

func (w *sseBatchWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	w.stopTimerLocked()
	if w.err != nil {
		return w.err
	}
	if err := w.flushLocked(); err != nil {
		w.err = err
		return err
	}
	if len(w.pendingInput) > 0 {
		_, err := w.w.Write(w.pendingInput)
		w.pendingInput = nil
		if err != nil {
			w.err = err
		}
		return err
	}
	return nil
}

func (w *sseBatchWriter) handleEventLocked(raw []byte) error {
	event, ok := parseBatchableSSE(raw)
	if !ok {
		if err := w.flushLocked(); err != nil {
			return err
		}
		_, err := w.w.Write(raw)
		return err
	}
	if !w.firstContentSent {
		w.firstContentSent = true
		_, err := w.w.Write(raw)
		return err
	}
	if w.bufferedEvent == nil {
		w.bufferLocked(raw, event)
		if w.bufferedContent > w.maxBytes {
			return w.flushLocked()
		}
		return nil
	}
	if !mergeBatchEvents(w.bufferedChoice, w.bufferedDelta, event) {
		if err := w.flushLocked(); err != nil {
			return err
		}
		_, err := w.w.Write(raw)
		return err
	}
	w.bufferedRaw = nil
	w.bufferedContent += len(batchContent(event.delta))
	if w.bufferedContent > w.maxBytes {
		return w.flushLocked()
	}
	return nil
}

func (w *sseBatchWriter) bufferLocked(raw []byte, event batchEvent) {
	w.bufferedRaw = append(w.bufferedRaw[:0], raw...)
	w.bufferedEvent = event.object
	w.bufferedChoice = event.choice
	w.bufferedDelta = event.delta
	w.bufferedContent = len(batchContent(event.delta))
	w.resetTimerLocked()
}

func (w *sseBatchWriter) flushLocked() error {
	w.stopTimerLocked()
	if w.bufferedEvent == nil {
		return nil
	}
	var err error
	if len(w.bufferedRaw) > 0 {
		_, err = w.w.Write(w.bufferedRaw)
	} else {
		var encoded []byte
		encoded, err = json.Marshal(w.bufferedEvent)
		if err == nil {
			_, err = w.w.Write(append(append([]byte("data: "), encoded...), '\n', '\n'))
		}
	}
	w.bufferedRaw = nil
	w.bufferedEvent = nil
	w.bufferedChoice = nil
	w.bufferedDelta = nil
	w.bufferedContent = 0
	return err
}

func (w *sseBatchWriter) resetTimerLocked() {
	w.stopTimerLocked()
	w.timer = time.AfterFunc(w.interval, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.closed {
			return
		}
		if err := w.flushLocked(); err != nil {
			w.err = err
		}
	})
}

func (w *sseBatchWriter) stopTimerLocked() {
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
}

type batchEvent struct {
	object map[string]any
	choice map[string]any
	delta  map[string]any
}

func nextSSEEvent(buf []byte) (event, rest []byte, ok bool) {
	nl := bytes.Index(buf, []byte("\n\n"))
	crlf := bytes.Index(buf, []byte("\r\n\r\n"))
	switch {
	case nl < 0 && crlf < 0:
		return nil, buf, false
	case nl >= 0 && (crlf < 0 || nl < crlf):
		return buf[:nl+2], buf[nl+2:], true
	default:
		return buf[:crlf+4], buf[crlf+4:], true
	}
}

func parseBatchableSSE(raw []byte) (batchEvent, bool) {
	body := bytes.TrimSuffix(raw, []byte("\n\n"))
	body = bytes.TrimSuffix(body, []byte("\r\n\r\n"))
	lines := bytes.Split(body, []byte("\n"))
	if len(lines) != 1 {
		return batchEvent{}, false
	}
	line := bytes.TrimSuffix(lines[0], []byte("\r"))
	if !bytes.HasPrefix(line, []byte("data: ")) {
		return batchEvent{}, false
	}
	payload := line[len("data: "):]
	if bytes.Equal(bytes.TrimSpace(payload), []byte("[DONE]")) {
		return batchEvent{}, false
	}
	var obj map[string]any
	if err := json.Unmarshal(payload, &obj); err != nil {
		return batchEvent{}, false
	}
	choice, delta, ok := batchChoice(obj)
	if !ok {
		return batchEvent{}, false
	}
	return batchEvent{object: obj, choice: choice, delta: delta}, true
}

func batchChoice(obj map[string]any) (map[string]any, map[string]any, bool) {
	if obj["object"] != "chat.completion.chunk" {
		return nil, nil, false
	}
	if _, ok := obj["usage"]; ok {
		return nil, nil, false
	}
	choices, ok := obj["choices"].([]any)
	if !ok || len(choices) != 1 {
		return nil, nil, false
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		return nil, nil, false
	}
	if _, ok := jsonNumber(choice["index"]); !ok {
		return nil, nil, false
	}
	if v, ok := choice["finish_reason"]; ok && v != nil {
		return nil, nil, false
	}
	if _, ok := choice["logprobs"]; ok {
		return nil, nil, false
	}
	delta, ok := choice["delta"].(map[string]any)
	if !ok || len(delta) != 1 {
		return nil, nil, false
	}
	if _, ok := delta["content"].(string); !ok {
		return nil, nil, false
	}
	return choice, delta, true
}

func mergeBatchEvents(bufferedChoice, bufferedDelta map[string]any, incoming batchEvent) bool {
	bufferedIndex, ok := jsonNumber(bufferedChoice["index"])
	if !ok {
		return false
	}
	incomingIndex, ok := jsonNumber(incoming.choice["index"])
	if !ok || bufferedIndex != incomingIndex {
		return false
	}
	bufferedDelta["content"] = batchContent(bufferedDelta) + batchContent(incoming.delta)
	return true
}

func batchContent(delta map[string]any) string {
	content, _ := delta["content"].(string)
	return content
}

func jsonNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}
