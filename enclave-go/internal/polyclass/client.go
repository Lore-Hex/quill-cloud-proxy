// Package polyclass runs Polyphemus's prompt classifier, a static helper
// binary in the measured image, as one long-lived child process. Prompts go to
// it over a pipe and never leave the gateway; the helper has no network code.
package polyclass

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
	"unicode/utf8"
)

// MaxTextBytes bounds what is sent per request. The classifier reads at most
// 512 tokens from the start, which 16 KiB of text always covers.
const MaxTextBytes = 16 << 10

// startupTimeout covers loading the 735 MB weights on first use.
const startupTimeout = 60 * time.Second

// restartBackoff stops a helper that cannot start from stalling every
// request: callers fall back immediately until it passes.
const restartBackoff = 30 * time.Second

var (
	ErrUnavailable = errors.New("polyclass: classifier unavailable")
	ErrInvalid     = errors.New("polyclass: classifier rejected the request")
)

// Result is the helper's reply. Fields are content-free scores and labels.
type Result struct {
	Task            string  `json:"task"`
	TaskProbability float64 `json:"task_probability"`
	DomainKnowledge float64 `json:"domain_knowledge"`
	Tokens          int     `json:"tokens"`
}

type process struct {
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stop   func()
}

type starter func() (*process, error)

// Client serializes requests to one helper. A helper that misbehaves or
// stalls is killed and replaced on the next request.
type Client struct {
	mu      sync.Mutex
	start   starter
	proc    *process
	timeout time.Duration
	failed  time.Time
	now     func() time.Time
}

func newClient(start starter, timeout time.Duration) *Client {
	return &Client{start: start, timeout: timeout, now: time.Now}
}

// New returns a client for the measured helper; it starts on first use.
func New() *Client { return newClient(startHelper, 3*time.Second) }

// Warm starts the helper in the background so the first request does not
// pay for loading the weights.
func (c *Client) Warm() {
	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		_ = c.ensure()
	}()
}

// Truncate returns at most MaxTextBytes of text, cut on a rune boundary.
func Truncate(text string) string {
	if len(text) <= MaxTextBytes {
		return text
	}
	cut := MaxTextBytes
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}

func (c *Client) Classify(ctx context.Context, text string) (Result, error) {
	text = Truncate(text)
	if !utf8.ValidString(text) {
		return Result{}, ErrInvalid
	}
	line, err := json.Marshal(struct {
		Text string `json:"text"`
	}{text})
	if err != nil {
		return Result{}, ErrInvalid
	}
	line = append(line, '\n')

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensure(); err != nil {
		return Result{}, err
	}
	proc := c.proc
	type reply struct {
		raw []byte
		err error
	}
	done := make(chan reply, 1)
	go func() {
		if _, err := proc.stdin.Write(line); err != nil {
			done <- reply{err: err}
			return
		}
		raw, err := proc.stdout.ReadBytes('\n')
		done <- reply{raw, err}
	}()
	timer := time.NewTimer(c.timeout)
	defer timer.Stop()
	var got reply
	select {
	case got = <-done:
	case <-timer.C:
		c.reset()
		return Result{}, ErrUnavailable
	case <-ctx.Done():
		// The helper may still be mid-request; replace it rather than desync.
		c.reset()
		return Result{}, ctx.Err()
	}
	if got.err != nil {
		c.reset()
		return Result{}, ErrUnavailable
	}
	var out struct {
		Result
		Error string `json:"error"`
	}
	if err := json.Unmarshal(got.raw, &out); err != nil {
		c.reset()
		return Result{}, ErrUnavailable
	}
	if out.Error != "" {
		return Result{}, ErrInvalid
	}
	if out.Task == "" || out.DomainKnowledge < 0 || out.DomainKnowledge > 1 {
		c.reset()
		return Result{}, ErrUnavailable
	}
	return out.Result, nil
}

// ensure starts the helper if needed. The caller holds c.mu.
func (c *Client) ensure() error {
	if c.proc != nil {
		return nil
	}
	if !c.failed.IsZero() && c.now().Sub(c.failed) < restartBackoff {
		return ErrUnavailable
	}
	proc, err := c.start()
	if err != nil {
		c.failed = c.now()
		return ErrUnavailable
	}
	c.failed = time.Time{}
	c.proc = proc
	return nil
}

func (c *Client) reset() {
	if c.proc != nil {
		c.proc.stop()
		c.proc = nil
	}
}

// awaitReady consumes the helper's {"ready":true} line.
func awaitReady(stdout *bufio.Reader, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		raw, err := stdout.ReadBytes('\n')
		if err != nil {
			done <- err
			return
		}
		var ready struct {
			Ready bool `json:"ready"`
		}
		if json.Unmarshal(raw, &ready) != nil || !ready.Ready {
			done <- ErrUnavailable
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return ErrUnavailable
	}
}
