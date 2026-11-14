package main

import (
	"context"
	"io"
	"sync"
	"time"
)

// Serialize comments with complete SSE frames, not merely HTTP chunks: an
// adapter is allowed to split one event across multiple Write calls. Place
// this below usage/receipt writers so transport liveness is never metered.
type sseKeepaliveWriter struct {
	mu          sync.Mutex
	w           io.Writer
	boundary    bool
	lineContent bool
	writeErr    error
}

func (w *sseKeepaliveWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	n, err := w.w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.boundary = false
		w.writeErr = err
		return n, err
	}
	for _, b := range p {
		if b == '\n' {
			w.boundary = !w.lineContent
			w.lineContent = false
		} else if b != '\r' {
			w.lineContent = true
			w.boundary = false
		}
	}
	return n, nil
}

func (w *sseKeepaliveWriter) ping() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return w.writeErr
	}
	if !w.boundary {
		return nil
	}
	const comment = ": keepalive\n\n"
	n, err := io.WriteString(w.w, comment)
	if err == nil && n != len(comment) {
		err = io.ErrShortWrite
	}
	w.writeErr = err
	return err
}

func (w *sseKeepaliveWriter) ClientWriteErr() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeErr
}

func startSSEKeepalive(ctx context.Context, out io.Writer, interval time.Duration, failed func(error)) (*sseKeepaliveWriter, func()) {
	w := &sseKeepaliveWriter{w: out, boundary: true}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := w.ping(); err != nil {
					failed(err)
					return
				}
			}
		}
	}()
	return w, func() { cancel(); <-done }
}
