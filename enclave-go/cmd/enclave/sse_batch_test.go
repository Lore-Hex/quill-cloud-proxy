package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func contentEvent(content string) string {
	return contentEventWithIndex(0, content)
}

func contentEventWithIndex(index int, content string) string {
	return batchEventJSON(map[string]any{
		"id":      "chatcmpl_test",
		"object":  "chat.completion.chunk",
		"created": 123,
		"model":   "test-model",
		"choices": []map[string]any{{
			"index":         index,
			"delta":         map[string]any{"content": content},
			"finish_reason": nil,
		}},
	})
}

func batchEventJSON(v map[string]any) string {
	encoded, _ := json.Marshal(v)
	return "data: " + string(encoded) + "\n\n"
}

func writeAndClose(t *testing.T, w *sseBatchWriter, input string) string {
	t.Helper()
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if out, ok := w.w.(*lockedBuffer); ok {
		return out.String()
	}
	return ""
}

func newTestBatchWriter(out *lockedBuffer, interval time.Duration, maxBytes int) *sseBatchWriter {
	return &sseBatchWriter{w: out, interval: interval, maxBytes: maxBytes}
}

func TestSSEBatchConsecutiveContentDeltasMergeLosslessly(t *testing.T) {
	out := &lockedBuffer{}
	w := newTestBatchWriter(out, time.Hour, 4096)
	input := contentEvent("Hel") + contentEvent("lo") + contentEvent(", world")
	got := writeAndClose(t, w, input)

	if count := strings.Count(got, "data: "); count != 2 {
		t.Fatalf("events written = %d, want 2; output=%s", count, got)
	}
	if gotContent := streamContent(t, got); gotContent != "Hello, world" {
		t.Fatalf("content = %q, want %q", gotContent, "Hello, world")
	}
}

func TestSSEBatchFirstEventPassesThroughImmediately(t *testing.T) {
	out := &lockedBuffer{}
	w := newTestBatchWriter(out, time.Hour, 4096)
	first := contentEvent("first")
	if _, err := w.Write([]byte(first)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := out.String(); got != first {
		t.Fatalf("first output = %q, want raw first event %q", got, first)
	}
}

func TestSSEBatchNonMergeableEventsFlushAndPreserveOrder(t *testing.T) {
	tests := []struct {
		name  string
		event string
	}{
		{
			name: "tool_calls",
			event: batchEventJSON(map[string]any{
				"object": "chat.completion.chunk",
				"choices": []map[string]any{{
					"index": 0,
					"delta": map[string]any{"tool_calls": []any{
						map[string]any{"index": 0, "id": "call_1"},
					}},
					"finish_reason": nil,
				}},
			}),
		},
		{
			name: "role",
			event: batchEventJSON(map[string]any{
				"object": "chat.completion.chunk",
				"choices": []map[string]any{{
					"index": 0,
					"delta": map[string]any{"role": "assistant", "content": ""},
				}},
			}),
		},
		{
			name: "finish_reason",
			event: batchEventJSON(map[string]any{
				"object": "chat.completion.chunk",
				"choices": []map[string]any{{
					"index": 0, "delta": map[string]any{}, "finish_reason": "stop",
				}},
			}),
		},
		{
			name: "usage",
			event: batchEventJSON(map[string]any{
				"object":  "chat.completion.chunk",
				"choices": []map[string]any{{"index": 0, "delta": map[string]any{}}},
				"usage":   map[string]any{"total_tokens": 2},
			}),
		},
		{
			name: "logprobs",
			event: batchEventJSON(map[string]any{
				"object": "chat.completion.chunk",
				"choices": []map[string]any{{
					"index": 0, "delta": map[string]any{"content": "x"}, "logprobs": map[string]any{},
				}},
			}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := &lockedBuffer{}
			w := newTestBatchWriter(out, time.Hour, 4096)
			first := contentEvent("a")
			second := contentEvent("b")
			third := contentEvent("c")
			got := writeAndClose(t, w, first+second+third+tc.event)
			if !strings.Contains(got, "bc") {
				t.Fatalf("pending content was not flushed before non-mergeable event: %s", got)
			}
			if !strings.HasSuffix(got, tc.event) {
				t.Fatalf("non-mergeable event not preserved at end\ngot:  %q\nwant suffix: %q", got, tc.event)
			}
		})
	}
}

func TestSSEBatchDoneAndCloseFlush(t *testing.T) {
	t.Run("done flushes", func(t *testing.T) {
		out := &lockedBuffer{}
		w := newTestBatchWriter(out, time.Hour, 4096)
		done := "data: [DONE]\n\n"
		got := writeAndClose(t, w, contentEvent("a")+contentEvent("b")+contentEvent("c")+done)
		if !strings.Contains(got, "bc") || !strings.HasSuffix(got, done) {
			t.Fatalf("output = %q", got)
		}
	})

	t.Run("close flushes", func(t *testing.T) {
		out := &lockedBuffer{}
		w := newTestBatchWriter(out, time.Hour, 4096)
		got := writeAndClose(t, w, contentEvent("a")+contentEvent("b")+contentEvent("c"))
		if !strings.Contains(got, "bc") {
			t.Fatalf("output = %q", got)
		}
	})
}

func TestSSEBatchMalformedJSONPassesThroughRaw(t *testing.T) {
	out := &lockedBuffer{}
	w := newTestBatchWriter(out, time.Hour, 4096)
	bad := "data: {not-json}\n\n"
	got := writeAndClose(t, w, contentEvent("a")+contentEvent("b")+contentEvent("c")+bad+contentEvent("d"))
	if !strings.Contains(got, "bc") || !strings.Contains(got, bad) || !strings.HasSuffix(got, contentEvent("d")) {
		t.Fatalf("output = %q", got)
	}
}

func TestSSEBatchIntervalFlushFiresWithoutFurtherWrites(t *testing.T) {
	out := &lockedBuffer{}
	w := newTestBatchWriter(out, 10*time.Millisecond, 4096)
	if _, err := w.Write([]byte(contentEvent("a") + contentEvent("b"))); err != nil {
		t.Fatalf("Write: %v", err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), "b") {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timer did not flush output: %q", out.String())
}

func TestSSEBatchMaxBytesFlush(t *testing.T) {
	out := &lockedBuffer{}
	w := newTestBatchWriter(out, time.Hour, 2)
	if _, err := w.Write([]byte(contentEvent("a") + contentEvent("bc") + contentEvent("d"))); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "bcd") {
		t.Fatalf("max-byte flush did not fire, output = %q", got)
	}
}

func TestSSEBatchMultiChoiceAndIndexMismatchDoNotMerge(t *testing.T) {
	tests := []struct {
		name  string
		event string
	}{
		{
			name: "multi-choice",
			event: batchEventJSON(map[string]any{
				"object": "chat.completion.chunk",
				"choices": []map[string]any{
					{"index": 0, "delta": map[string]any{"content": "b"}},
					{"index": 1, "delta": map[string]any{"content": "c"}},
				},
			}),
		},
		{name: "index-mismatch", event: contentEventWithIndex(1, "b")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := &lockedBuffer{}
			w := newTestBatchWriter(out, time.Hour, 4096)
			got := writeAndClose(t, w, contentEvent("a")+contentEvent("x")+tc.event)
			if !strings.Contains(got, contentEvent("a")) {
				t.Fatalf("first event not preserved: %q", got)
			}
			if !strings.Contains(got, "x") || !strings.Contains(got, tc.event) {
				t.Fatalf("order not preserved: %q", got)
			}
		})
	}
}

func TestSSEBatchDisabledPassThrough(t *testing.T) {
	t.Setenv("TR_SSE_BATCH_MS", "0")
	var out bytes.Buffer
	w := newSSEBatchWriter(&out)
	input := ": comment\r\n\r\n" + contentEvent("a") + "event: ping\ndata: {}\n\n" + "data: {bad}\n\n"
	if _, err := w.Write([]byte(input[:17])); err != nil {
		t.Fatalf("Write first: %v", err)
	}
	if _, err := w.Write([]byte(input[17:])); err != nil {
		t.Fatalf("Write second: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := out.String(); got != input {
		t.Fatalf("pass-through mismatch\ngot:  %q\nwant: %q", got, input)
	}
}

func streamContent(t *testing.T, stream string) string {
	t.Helper()
	var out strings.Builder
	for _, block := range strings.Split(stream, "\n\n") {
		if block == "" || block == "data: [DONE]" || !strings.HasPrefix(block, "data: ") {
			continue
		}
		var parsed struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(block, "data: ")), &parsed); err != nil {
			t.Fatalf("unmarshal output block %q: %v", block, err)
		}
		for _, choice := range parsed.Choices {
			out.WriteString(choice.Delta.Content)
		}
	}
	return out.String()
}
