package polyclass

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeHelper speaks the helper's protocol over pipes. respond maps each
// request's text to the raw reply line; "" means never reply.
type fakeHelper struct {
	started atomic.Int32
	stopped atomic.Int32
	seen    chan string
	respond func(text string) string
}

func (f *fakeHelper) start() (*process, error) {
	f.started.Add(1)
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
			if reply := f.respond(req.Text); reply != "" {
				if _, err := io.WriteString(respW, reply+"\n"); err != nil {
					return
				}
			}
		}
	}()
	stdout := bufio.NewReader(respR)
	if err := awaitReady(stdout, time.Second); err != nil {
		return nil, err
	}
	return &process{stdin: reqW, stdout: stdout, stop: func() {
		f.stopped.Add(1)
		_ = reqW.Close()
		_ = respR.Close()
		_ = reqR.Close()
		_ = respW.Close()
	}}, nil
}

const codeReply = `{"task":"Code Generation","task_probability":0.77,"domain_knowledge":0.98,"tokens":14}`

func TestClassifyReturnsHelperScores(t *testing.T) {
	f := &fakeHelper{respond: func(string) string { return codeReply }}
	c := newClient(f.start, time.Second)
	got, err := c.Classify(context.Background(), "write a for loop")
	if err != nil {
		t.Fatal(err)
	}
	if got.Task != "Code Generation" || got.DomainKnowledge != 0.98 || got.Tokens != 14 {
		t.Fatalf("got %+v", got)
	}
	if _, err := c.Classify(context.Background(), "again"); err != nil {
		t.Fatal(err)
	}
	if f.started.Load() != 1 {
		t.Fatalf("helper started %d times, want one long-lived process", f.started.Load())
	}
}

func TestHelperErrorIsInvalidAndKeepsProcess(t *testing.T) {
	f := &fakeHelper{respond: func(string) string { return `{"error":"invalid_request"}` }}
	c := newClient(f.start, time.Second)
	if _, err := c.Classify(context.Background(), "x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if f.stopped.Load() != 0 {
		t.Fatal("a well-formed refusal must not restart the helper")
	}
}

func TestMalformedOrOutOfRangeReplyRestartsHelper(t *testing.T) {
	for _, reply := range []string{"not json", `{"task":""}`, `{"task":"Open QA","domain_knowledge":1.5}`} {
		f := &fakeHelper{respond: func(string) string { return reply }}
		c := newClient(f.start, time.Second)
		if _, err := c.Classify(context.Background(), "x"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%q: err = %v", reply, err)
		}
		if f.stopped.Load() != 1 {
			t.Fatalf("%q: helper not replaced", reply)
		}
		f.respond = func(string) string { return codeReply }
		if _, err := c.Classify(context.Background(), "x"); err != nil || f.started.Load() != 2 {
			t.Fatalf("%q: no fresh helper after reset: %v", reply, err)
		}
	}
}

func TestStalledHelperTimesOutAndIsReplaced(t *testing.T) {
	f := &fakeHelper{respond: func(string) string { return "" }}
	c := newClient(f.start, 50*time.Millisecond)
	started := time.Now()
	if _, err := c.Classify(context.Background(), "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(started) > time.Second || f.stopped.Load() != 1 {
		t.Fatal("stalled helper was not abandoned promptly")
	}
}

func TestCancelledRequestReplacesHelper(t *testing.T) {
	f := &fakeHelper{respond: func(string) string { return "" }}
	c := newClient(f.start, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if _, err := c.Classify(ctx, "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if f.stopped.Load() != 1 {
		t.Fatal("helper with an unread reply must be replaced")
	}
}

func TestStartFailureBacksOff(t *testing.T) {
	starts := 0
	c := newClient(func() (*process, error) { starts++; return nil, errors.New("boom") }, time.Second)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	for range 3 {
		if _, err := c.Classify(context.Background(), "x"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v", err)
		}
	}
	if starts != 1 {
		t.Fatalf("started %d times inside the backoff window", starts)
	}
	now = now.Add(restartBackoff)
	_, _ = c.Classify(context.Background(), "x")
	if starts != 2 {
		t.Fatalf("no retry after the backoff window: %d", starts)
	}
}

func TestOversizedTextIsTruncatedOnRuneBoundary(t *testing.T) {
	f := &fakeHelper{seen: make(chan string, 1), respond: func(string) string { return codeReply }}
	c := newClient(f.start, time.Second)
	text := strings.Repeat("a", MaxTextBytes-1) + "é" + "tail"
	if _, err := c.Classify(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	sent := <-f.seen
	if len(sent) != MaxTextBytes-1 || strings.Contains(sent, "tail") {
		t.Fatalf("sent %d bytes", len(sent))
	}
	if _, err := c.Classify(context.Background(), "\xff\xfe"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid UTF-8 err = %v", err)
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
