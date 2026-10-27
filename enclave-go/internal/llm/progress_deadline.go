package llm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

const (
	hixtubeCompletionTimeout = 60 * time.Minute
	hixtubeProgressTimeout   = 30 * time.Second
)

// progressDeadlineTransport bounds headers, the first byte and later read
// stalls without replacing the cloud-specific transport or extending the
// caller's context/total deadline. It is opt-in for long streaming providers.
type progressDeadlineTransport struct {
	base    http.RoundTripper
	timeout time.Duration
}

func (t *progressDeadlineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(req.Context())
	timer := time.AfterFunc(t.timeout, func() { cancel(context.DeadlineExceeded) })
	response, err := t.base.RoundTrip(req.Clone(ctx))
	if err != nil || response == nil || response.Body == nil {
		err = progressDeadlineError(req.Context(), ctx, err)
		timer.Stop()
		cancel(nil)
		return response, err
	}
	timer.Reset(t.timeout)
	response.Body = &progressDeadlineBody{ReadCloser: response.Body, timer: timer, cancel: cancel, timeout: t.timeout, parent: req.Context(), ctx: ctx}
	return response, nil
}

func (t *progressDeadlineTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type progressDeadlineBody struct {
	io.ReadCloser
	timer   *time.Timer
	cancel  context.CancelCauseFunc
	timeout time.Duration
	parent  context.Context
	ctx     context.Context
}

func (b *progressDeadlineBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.timer.Reset(b.timeout)
	}
	if err != nil {
		err = progressDeadlineError(b.parent, b.ctx, err)
		b.timer.Stop()
		b.cancel(nil)
	}
	return n, err
}

func (b *progressDeadlineBody) Close() error {
	b.timer.Stop()
	b.cancel(nil)
	return b.ReadCloser.Close()
}

func progressDeadlineError(parent, child context.Context, err error) error {
	if err != nil && parent.Err() == nil && errors.Is(context.Cause(child), context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return err
}
