// Package polyclass runs Polyphemus's prompt classifier, a static helper
// binary in the measured image, as one long-lived child process. Prompts go to
// it over a pipe and never leave the gateway; the helper has no network code.
//
// The helper answers one request at a time. Callers wait a bounded time for
// it and otherwise fail fast, so Polyphemus falls back instead of queueing.
// Starting and restarting happen only in the background, never on a
// request's path, and restarts are rate limited so a client that keeps
// disconnecting cannot make the gateway reload the weights repeatedly.
package polyclass

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// MaxTextBytes bounds what is sent per request. The classifier reads at most
// 512 tokens from the start, which 16 KiB of text always covers.
const MaxTextBytes = 16 << 10

// startupTimeout covers loading the 735 MB weights.
const startupTimeout = 60 * time.Second

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

type Client struct {
	start starter
	// slot is held for exactly one in-flight helper request.
	slot chan struct{}
	// wait bounds how long a caller queues for the slot and answer bounds
	// how long it waits for a reply; past either it falls back. stuck is how
	// long one inference may run before the helper is replaced, whether or
	// not its caller is still waiting. A slow prompt costs one fallback, not
	// a reload of the weights.
	wait, answer, stuck time.Duration
	// backoff is the minimum time between helper start attempts.
	backoff time.Duration
	now     func() time.Time
	// onStuck runs when the watchdog fires; tests delay it.
	onStuck func(*process)

	mu        sync.Mutex
	proc      *process
	starting  bool
	scheduled bool
	lastStart time.Time
}

func newClient(start starter, wait, answer, stuck, backoff time.Duration) *Client {
	c := &Client{start: start, slot: make(chan struct{}, 1), wait: wait, answer: answer, stuck: stuck, backoff: backoff, now: time.Now}
	c.onStuck = c.retire
	return c
}

// New returns a client for the measured helper. Call Warm to start it.
func New() *Client {
	return newClient(startHelper, 1500*time.Millisecond, 3*time.Second, 10*time.Second, 15*time.Second)
}

// Warm starts the helper in the background.
func (c *Client) Warm() { c.startAsync() }

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

// startAsync launches the helper unless it is running or starting. Inside
// the backoff window it schedules one attempt for the window's end, so
// recovery never waits for traffic.
func (c *Client) startAsync() {
	c.mu.Lock()
	if c.proc != nil || c.starting {
		c.mu.Unlock()
		return
	}
	if !c.lastStart.IsZero() {
		if remaining := c.backoff - c.now().Sub(c.lastStart); remaining > 0 {
			if !c.scheduled {
				c.scheduled = true
				time.AfterFunc(remaining, func() {
					c.mu.Lock()
					c.scheduled = false
					c.mu.Unlock()
					c.startAsync()
				})
			}
			c.mu.Unlock()
			return
		}
	}
	c.starting = true
	c.lastStart = c.now()
	c.mu.Unlock()
	go func() {
		proc, err := c.start()
		c.mu.Lock()
		defer c.mu.Unlock()
		c.starting = false
		if err == nil {
			c.proc = proc
		}
	}()
}

// retire stops proc if it is still current and schedules a replacement.
func (c *Client) retire(proc *process) {
	c.mu.Lock()
	current := c.proc == proc
	if current {
		c.proc = nil
	}
	c.mu.Unlock()
	if current {
		proc.stop()
	}
	c.startAsync()
}

type reply struct {
	result Result
	err    error
}

func (c *Client) Classify(ctx context.Context, text string) (Result, error) {
	text = Truncate(text)
	if strings.TrimSpace(text) == "" || !utf8.ValidString(text) {
		return Result{}, ErrInvalid
	}
	line, err := json.Marshal(struct {
		Text string `json:"text"`
	}{text})
	if err != nil {
		return Result{}, ErrInvalid
	}
	line = append(line, '\n')

	wait := time.NewTimer(c.wait)
	defer wait.Stop()
	select {
	case c.slot <- struct{}{}:
	case <-wait.C:
		return Result{}, ErrUnavailable
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	c.mu.Lock()
	proc := c.proc
	c.mu.Unlock()
	if proc == nil {
		<-c.slot
		c.startAsync()
		return Result{}, ErrUnavailable
	}

	done := make(chan reply, 1)
	// The request owns the slot until the helper answers or is killed, even
	// if its caller leaves, so the next request never reads a stale reply.
	onStuck := c.onStuck
	watchdog := time.AfterFunc(c.stuck, func() { onStuck(proc) })
	go func() {
		defer func() { <-c.slot }()
		got := exchange(proc, line)
		// A watchdog that already fired may still be retiring proc; finish
		// that here so the next request never picks up a dying helper.
		fired := !watchdog.Stop()
		if fired || (got.err != nil && !errors.Is(got.err, ErrInvalid)) {
			c.retire(proc)
		}
		if fired {
			got = reply{err: ErrUnavailable}
		}
		done <- got
	}()
	answer := time.NewTimer(c.answer)
	defer answer.Stop()
	select {
	case got := <-done:
		return got.result, got.err
	case <-answer.C:
		return Result{}, ErrUnavailable
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}

// exchange sends one request and reads one reply. ErrInvalid is the helper's
// well-formed refusal; any other error means the helper must be replaced.
func exchange(proc *process, line []byte) reply {
	if _, err := proc.stdin.Write(line); err != nil {
		return reply{err: ErrUnavailable}
	}
	raw, err := proc.stdout.ReadBytes('\n')
	if err != nil {
		return reply{err: ErrUnavailable}
	}
	var out struct {
		Result
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return reply{err: ErrUnavailable}
	}
	if out.Error != "" {
		return reply{err: ErrInvalid}
	}
	if out.Task == "" || out.DomainKnowledge < 0 || out.DomainKnowledge > 1 {
		return reply{err: ErrUnavailable}
	}
	return reply{result: out.Result}
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
