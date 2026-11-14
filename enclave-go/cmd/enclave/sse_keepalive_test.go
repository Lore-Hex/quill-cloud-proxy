package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestSSEKeepaliveNeverSplitsAnEvent(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		var out bytes.Buffer
		w := &sseKeepaliveWriter{w: &out, boundary: true}
		parts := []string{"data: {\"a\":", "1}", newline, newline}
		for i, part := range parts {
			if _, err := io.WriteString(w, part); err != nil {
				t.Fatal(err)
			}
			if err := w.ping(); err != nil {
				t.Fatal(err)
			}
			if i < len(parts)-1 && strings.Contains(out.String(), ": keepalive") {
				t.Fatal("comment inside an event")
			}
		}
		if out.String() != strings.Join(parts, "")+": keepalive\n\n" {
			t.Fatalf("wire = %q", out.String())
		}
	}
}

func TestSSEKeepaliveIsNotUsageAndStopsBeforeCompletion(t *testing.T) {
	var out synchronizedBuffer
	chunked := newChunkedWriter(&out)
	w, stop := startSSEKeepalive(t.Context(), chunked, time.Millisecond, func(err error) { t.Error(err) })
	defer stop()
	stats := newStreamStatsWriter(w)
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(out.String(), ": keepalive") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(out.String(), ": keepalive") {
		t.Fatal("no heartbeat while model idle")
	}
	if stats.BytesWritten() != 0 {
		t.Fatal("heartbeat counted as delivered model output")
	}
	stop()
	if _, err := io.WriteString(stats, "data: [DONE]\n\n"); err != nil {
		t.Fatal(err)
	}
	if err := chunked.Complete(); err != nil {
		t.Fatal(err)
	}
	wire := out.String()
	time.Sleep(5 * time.Millisecond)
	if out.String() != wire {
		t.Fatal("heartbeat after completion")
	}
}

type keepaliveFailureWriter struct{}

func (keepaliveFailureWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestSSEKeepaliveFailureCancelsProvider(t *testing.T) {
	failed := make(chan error, 1)
	w, stop := startSSEKeepalive(t.Context(), keepaliveFailureWriter{}, time.Millisecond, func(err error) { failed <- err })
	defer stop()
	select {
	case err := <-failed:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("write failure did not reach provider cancellation")
	}
	if !errors.Is(w.ClientWriteErr(), io.ErrClosedPipe) {
		t.Fatal("keepalive failure lost client attribution")
	}
	if _, err := io.WriteString(w, "data: [DONE]\n\n"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("terminal write after failed keepalive = %v", err)
	}
}
