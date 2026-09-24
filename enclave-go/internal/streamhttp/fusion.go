// Package streamhttp applies request-scoped deadlines to upstream inference.
package streamhttp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type fusionTimeoutKey struct{}
type timeouts struct{ idle, total time.Duration }

// WithFusionTimeout opts a fusion inference call into a progress deadline.
// Panel/judge calls stream upstream even when their collected response does not.
// Direct calls, authorization, OAuth and attestation keep their own deadlines.
func WithFusionTimeout(ctx context.Context) context.Context {
	// Match the existing five-minute last-candidate first-byte allowance so
	// a reasoning model that is initially silent does not get a shorter budget.
	return context.WithValue(ctx, fusionTimeoutKey{}, timeouts{5 * time.Minute, 30 * time.Minute})
}

// Client adapts Do for SDKs that accept an HTTP client interface.
type Client struct{ Base *http.Client }

func (c Client) Do(req *http.Request) (*http.Response, error) { return Do(c.Base, req) }

// Do preserves the client's transport (including attestation/vsock), redirects
// and cookie policy. Only opted-in requests replace its total timeout.
func Do(client *http.Client, req *http.Request) (*http.Response, error) {
	limits, ok := req.Context().Value(fusionTimeoutKey{}).(timeouts)
	if !ok {
		return client.Do(req)
	}
	ctx, cancel := context.WithCancelCause(req.Context())
	watch := &progressWatch{cancel: cancel, idle: limits.idle, last: time.Now()}
	watch.mu.Lock()
	watch.timer = time.AfterFunc(limits.idle, watch.expire)
	watch.mu.Unlock()
	copyClient := *client
	copyClient.Timeout = limits.total
	resp, err := copyClient.Do(req.Clone(ctx))
	if err != nil {
		cause := context.Cause(ctx)
		watch.stop()
		if cause != nil {
			return nil, cause
		}
		return nil, err
	}
	watch.progress()
	resp.Body = &progressBody{ReadCloser: resp.Body, watch: watch, ctx: ctx}
	return resp, nil
}

// One timer per request, with no goroutine per Read. Canceling the request
// interrupts both header waits and blocked body reads, including HTTP/2 streams.
type progressWatch struct {
	mu      sync.Mutex
	timer   *time.Timer
	cancel  context.CancelCauseFunc
	idle    time.Duration
	last    time.Time
	stopped bool
}

func (w *progressWatch) expire() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	// A read may have made progress while this callback waited for the lock.
	if remaining := w.idle - time.Since(w.last); remaining > 0 {
		w.timer.Reset(remaining)
		return
	}
	w.stopped = true
	w.cancel(fmt.Errorf("fusion upstream idle timeout after %s: %w", w.idle, context.DeadlineExceeded))
}

func (w *progressWatch) progress() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.stopped {
		w.last = time.Now()
	}
}

func (w *progressWatch) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = true
	w.timer.Stop()
	w.cancel(context.Canceled)
}

type progressBody struct {
	io.ReadCloser
	watch *progressWatch
	ctx   context.Context
}

func (b *progressBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.watch.progress()
	}
	if err != nil {
		cause := context.Cause(b.ctx)
		b.watch.stop()
		if cause != nil {
			return n, cause
		}
	}
	return n, err
}

func (b *progressBody) Close() error {
	b.watch.stop()
	return b.ReadCloser.Close()
}
