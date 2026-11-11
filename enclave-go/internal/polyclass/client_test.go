package polyclass

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeHelper speaks the helper's protocol over pipes. respond returns the
// raw reply line for a request's text after an optional delay; "" means
// never reply.
type fakeHelper struct {
	started atomic.Int32
	stopped atomic.Int32
	failing atomic.Bool
	seen    chan string
	mu      sync.Mutex
	respond func(text string) (string, time.Duration)
}

func (f *fakeHelper) setRespond(fn func(string) (string, time.Duration)) {
	f.mu.Lock()
	f.respond = fn
	f.mu.Unlock()
}

func (f *fakeHelper) reply(text string) (string, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.respond(text)
}

func (f *fakeHelper) start() (*process, error) {
	f.started.Add(1)
	if f.failing.Load() {
		return nil, errors.New("cannot start")
	}
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() {
		_, _ = io.WriteString(respW, "{\"ready\":true}\n")
		in := bufio.NewReader(reqR)
		for {
			line, err := in.ReadBytes('\n')
			if err != nil {
				return
			}
			var req struct{ Text string }
			_ = json.Unmarshal(line, &req)
			if f.seen != nil {
				f.seen <- req.Text
			}
			out, delay := f.reply(req.Text)
			time.Sleep(delay)
			if out != "" {
				if _, err := io.WriteString(respW, out+"\n"); err != nil {
					return
				}
			}
		}
	}()
	stdout := bufio.NewReader(respR)
	if err := awaitReady(stdout, time.Second); err != nil {
		return nil, err
	}
	var once sync.Once
	return &process{stdin: reqW, stdout: stdout, stop: func() {
		once.Do(func() {
			f.stopped.Add(1)
			_ = reqW.Close()
			_ = respR.Close()
			_ = reqR.Close()
			_ = respW.Close()
		})
	}}, nil
}

const codeReply = `{"task":"Code Generation","task_probability":0.77,"domain_knowledge":0.98,"tokens":14}`

func always(out string) func(string) (string, time.Duration) {
	return func(string) (string, time.Duration) { return out, 0 }
}

// warmClient returns a client whose helper is running.
func warmClient(t *testing.T, f *fakeHelper, wait, timeout time.Duration) *Client {
	t.Helper()
	c := newClient(f.start, wait, timeout, time.Hour)
	c.Warm()
	eventually(t, func() bool { return c.running() })
	return c
}

func (c *Client) running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.proc != nil
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestClassifyReturnsHelperScoresFromOneProcess(t *testing.T) {
	f := &fakeHelper{respond: always(codeReply)}
	c := warmClient(t, f, time.Second, time.Second)
	for range 3 {
		got, err := c.Classify(context.Background(), "write a for loop")
		if err != nil {
			t.Fatal(err)
		}
		if got.Task != "Code Generation" || got.DomainKnowledge != 0.98 || got.Tokens != 14 {
			t.Fatalf("got %+v", got)
		}
	}
	if f.started.Load() != 1 {
		t.Fatalf("helper started %d times, want one long-lived process", f.started.Load())
	}
}

func TestColdClientFailsFastAndStartsInBackground(t *testing.T) {
	f := &fakeHelper{respond: always(codeReply)}
	c := newClient(f.start, time.Second, time.Second, time.Hour)
	started := time.Now()
	if _, err := c.Classify(context.Background(), "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("a request waited for the helper to start")
	}
	eventually(t, c.running)
	if _, err := c.Classify(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
}

func TestBusyHelperBoundsTheWaitAndHonorsCancellation(t *testing.T) {
	f := &fakeHelper{respond: always(codeReply)}
	c := warmClient(t, f, 50*time.Millisecond, time.Minute)
	release := make(chan struct{})
	f.setRespond(func(string) (string, time.Duration) { <-release; return codeReply, 0 })
	first := make(chan error, 1)
	go func() { _, err := c.Classify(context.Background(), "slow"); first <- err }()
	eventually(t, func() bool { return len(c.slot) == 1 })

	started := time.Now()
	if _, err := c.Classify(context.Background(), "queued"); !errors.Is(err, ErrUnavailable) || time.Since(started) > time.Second {
		t.Fatalf("queued request: %v after %s", err, time.Since(started))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Classify(ctx, "cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter: %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if f.stopped.Load() != 0 {
		t.Fatal("waiting callers disturbed the helper")
	}
}

func TestCancelledCallerDoesNotKillTheHelper(t *testing.T) {
	f := &fakeHelper{respond: always(codeReply)}
	c := warmClient(t, f, time.Second, time.Minute)
	f.setRespond(func(text string) (string, time.Duration) {
		if text == "slow" {
			return `{"task":"Open QA","task_probability":0.9,"domain_knowledge":0.3,"tokens":3}`, 100 * time.Millisecond
		}
		return codeReply, 0
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := c.Classify(ctx, "slow"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	// The abandoned reply is drained before the slot frees, so the next
	// request gets its own answer from the same process.
	got, err := c.Classify(context.Background(), "next")
	if err != nil || got.Task != "Code Generation" {
		t.Fatalf("next request got %+v, %v", got, err)
	}
	if f.stopped.Load() != 0 || f.started.Load() != 1 {
		t.Fatalf("disconnect restarted the helper: started=%d stopped=%d", f.started.Load(), f.stopped.Load())
	}
}

func TestStalledHelperIsKilledAndRestartedInBackground(t *testing.T) {
	f := &fakeHelper{respond: always(codeReply)}
	c := newClient(f.start, time.Second, 50*time.Millisecond, 0)
	c.Warm()
	eventually(t, c.running)
	f.setRespond(always(""))
	started := time.Now()
	if _, err := c.Classify(context.Background(), "x"); !errors.Is(err, ErrUnavailable) || time.Since(started) > time.Second {
		t.Fatalf("stalled helper: %v after %s", err, time.Since(started))
	}
	eventually(t, func() bool { return f.stopped.Load() == 1 && f.started.Load() == 2 && c.running() })
	f.setRespond(always(codeReply))
	if _, err := c.Classify(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
}

func TestAbandonedStallIsStillKilledByTheWatchdog(t *testing.T) {
	f := &fakeHelper{respond: always("")}
	c := warmClient(t, f, time.Second, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	go func() { _, _ = c.Classify(context.Background(), "x") }()
	_, _ = c.Classify(ctx, "y")
	eventually(t, func() bool { return f.stopped.Load() == 1 && len(c.slot) == 0 })
}

func TestMalformedOrOutOfRangeReplyReplacesHelper(t *testing.T) {
	for _, bad := range []string{"not json", `{"task":""}`, `{"task":"Open QA","domain_knowledge":1.5}`} {
		f := &fakeHelper{respond: always(bad)}
		c := newClient(f.start, time.Second, time.Second, 0)
		c.Warm()
		eventually(t, c.running)
		if _, err := c.Classify(context.Background(), "x"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%q: err = %v", bad, err)
		}
		eventually(t, func() bool { return f.stopped.Load() == 1 && f.started.Load() == 2 })
	}
}

func TestHelperRefusalKeepsTheProcess(t *testing.T) {
	f := &fakeHelper{respond: always(`{"error":"invalid_request"}`)}
	c := warmClient(t, f, time.Second, time.Second)
	if _, err := c.Classify(context.Background(), "x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if f.stopped.Load() != 0 {
		t.Fatal("a well-formed refusal restarted the helper")
	}
}

func TestRestartsAreRateLimited(t *testing.T) {
	f := &fakeHelper{respond: always(codeReply)}
	f.failing.Store(true)
	c := newClient(f.start, time.Second, time.Second, 30*time.Second)
	now := time.Unix(1000, 0)
	var clock sync.Mutex
	c.now = func() time.Time { clock.Lock(); defer clock.Unlock(); return now }
	c.Warm()
	eventually(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return !c.starting })
	for range 5 {
		_, _ = c.Classify(context.Background(), "x")
	}
	time.Sleep(20 * time.Millisecond)
	if f.started.Load() != 1 {
		t.Fatalf("started %d times inside the backoff window", f.started.Load())
	}
	f.failing.Store(false)
	clock.Lock()
	now = now.Add(30 * time.Second)
	clock.Unlock()
	_, _ = c.Classify(context.Background(), "x")
	eventually(t, c.running)
	if f.started.Load() != 2 {
		t.Fatalf("no retry after the backoff window: %d", f.started.Load())
	}
}

func TestTextIsTruncatedOnRuneBoundaryAndBlankIsRefused(t *testing.T) {
	f := &fakeHelper{seen: make(chan string, 1), respond: always(codeReply)}
	c := warmClient(t, f, time.Second, time.Second)
	text := strings.Repeat("a", MaxTextBytes-1) + "é" + "tail"
	if _, err := c.Classify(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	if sent := <-f.seen; len(sent) != MaxTextBytes-1 || strings.Contains(sent, "tail") {
		t.Fatalf("sent %d bytes", len(sent))
	}
	for _, bad := range []string{"\xff\xfe", "", strings.Repeat(" ", MaxTextBytes) + "text after the cut"} {
		if _, err := c.Classify(context.Background(), bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%.20q: err = %v", bad, err)
		}
	}
}

func TestAwaitReadyRejectsWrongHandshake(t *testing.T) {
	if err := awaitReady(bufio.NewReader(strings.NewReader("{\"ready\":false}\n")), time.Second); err == nil {
		t.Fatal("accepted ready:false")
	}
	r, _ := io.Pipe()
	if err := awaitReady(bufio.NewReader(r), 20*time.Millisecond); err == nil {
		t.Fatal("no timeout on a silent helper")
	}
}
