package requesttiming

import (
	"context"
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time   { return c.now }
func (c *fakeClock) advance(ms int64) { c.now = c.now.Add(time.Duration(ms) * time.Millisecond) }
func newFakeTimer() (*Timer, *fakeClock) {
	c := &fakeClock{now: time.Unix(1000, 0)}
	return New(c.Now(), c.Now), c
}
func assertPhaseSum(t *testing.T, timer *Timer, elapsed time.Duration) {
	t.Helper()
	f := timer.Snapshot()
	sum := f.AcceptToStartMS + f.AuthorizeMS + f.RouteMS + f.UpstreamMS + f.RetryWaitMS + f.SettleMS + f.ReceiptMS
	if sum != elapsed.Milliseconds() {
		t.Fatalf("phase sum=%d elapsed=%d: %+v", sum, elapsed.Milliseconds(), f)
	}
}

func TestPhaseTimerMissingAndFrozen(t *testing.T) {
	var absent *Timer
	want := Fields{SettleOutcome: "skipped"}
	if got := absent.Snapshot(); got != want {
		t.Fatalf("nil snapshot = %+v", got)
	}
	timer, c := newFakeTimer()
	if FromContext(WithTimer(context.Background(), timer)) != timer {
		t.Fatal("lost timer")
	}
	timer.End()
	c.advance(10)
	timer.Start()
	timer.AuthorizeDone(c.Now().Add(-time.Second))
	timer.AuthorizeAttempt("https://ignored.example")
	invocation := timer.InvokeStart()
	timer.FirstByte(invocation)
	timer.InvokeComplete(invocation)
	timer.SettleDone(c.Now(), "failed")
	timer.RetryWaitDone(c.Now().Add(-time.Second))
	if got := timer.Snapshot(); got != want {
		t.Fatalf("missing/frozen phases = %+v", got)
	}
}

func TestPhaseTimerExactAndReadOrder(t *testing.T) {
	timer, c := newFakeTimer()
	c.advance(12)
	timer.Start()
	for i := 0; i < 2; i++ {
		start := c.Now()
		timer.AuthorizeAttempt("https://user:secret@cp.example:8443/private?token=secret#secret")
		c.advance(4)
		timer.AuthorizeDone(start)
	}
	_ = timer.Snapshot()
	c.advance(20)
	invocation := timer.InvokeStart()
	c.advance(9)
	timer.FirstByte(invocation)
	c.advance(8)
	timer.FirstByte(invocation) // only the first byte counts
	timer.InvokeComplete(invocation)
	start := c.Now()
	c.advance(3)
	timer.SettleDone(start, "ok")
	c.advance(12)
	elapsed := timer.End()
	want := Fields{AcceptToStartMS: 12, AuthorizeMS: 8, AuthorizeAttempts: 2, RouteMS: 20, UpstreamMS: 17, TTFBMS: 9, SettleMS: 3, ReceiptMS: 12, SettleOutcome: "ok", CPEndpoint: "cp.example"}
	if got := timer.Snapshot(); got != want {
		t.Fatalf("fields=%+v want=%+v", got, want)
	}
	assertPhaseSum(t, timer, elapsed)
	c.advance(100)
	late := timer.InvokeStart()
	timer.FirstByte(late)
	timer.InvokeComplete(late)
	if got := timer.Snapshot(); got != want || timer.End() != elapsed {
		t.Fatalf("frozen fields=%+v", got)
	}
}

func TestPhaseTimerRealClockSmoke(t *testing.T) {
	timer := New(time.Now(), nil)
	if timer.accepted == timer.accepted.Round(0) {
		t.Fatal("lost monotonic clock")
	}
	timer.Start()
	invocation := timer.InvokeStart()
	timer.FirstByte(invocation)
	timer.InvokeComplete(invocation)
	elapsed := timer.End()
	f := timer.Snapshot()
	for _, n := range []int64{elapsed.Nanoseconds(), f.AcceptToStartMS, f.AuthorizeMS, f.RouteMS, f.UpstreamMS, f.TTFBMS, f.RetryWaitMS, f.SettleMS, f.ReceiptMS} {
		if n < 0 {
			t.Fatalf("negative duration: %+v", f)
		}
	}
	if timer.End() != elapsed || timer.Now().Before(timer.accepted) {
		t.Fatal("clock moved backwards")
	}
}

func TestPhaseTimerMissingInvokeAndEndpointBounds(t *testing.T) {
	timer, c := newFakeTimer()
	timer.Start()
	timer.AuthorizeAttempt("https://" + strings.Repeat("x", 254) + "/secret")
	start := c.Now()
	c.advance(2)
	timer.AuthorizeDone(start)
	timer.End()
	want := Fields{AuthorizeMS: 2, AuthorizeAttempts: 1, SettleOutcome: "skipped"}
	if got := timer.Snapshot(); got != want {
		t.Fatalf("missing invoke=%+v", got)
	}
}

func TestPhaseTimerSettlementOutcomes(t *testing.T) {
	for _, outcome := range []string{"ok", "failed", "deferred"} {
		t.Run(outcome, func(t *testing.T) {
			timer, c := newFakeTimer()
			start := c.Now()
			c.advance(2)
			timer.SettleDone(start, outcome)
			timer.End()
			if got := timer.Snapshot(); got.SettleOutcome != outcome || got.SettleMS != 2 {
				t.Fatalf("settle=%+v", got)
			}
		})
	}
}

func TestPhaseTimerAuthorizationCompletesAfterInvokeStart(t *testing.T) {
	timer, c := newFakeTimer()
	timer.Start()
	start := c.Now()
	c.advance(5)
	timer.InvokeStart()
	before := timer.Snapshot()
	timer.AuthorizeDone(start)
	timer.End()
	after := timer.Snapshot()
	if before.RouteMS != 5 || after.AuthorizeMS != 5 || after.RouteMS != 0 {
		t.Fatalf("late authorize: before=%+v after=%+v", before, after)
	}
}

func TestPhaseTimerProviderCompletesAfterEnd(t *testing.T) {
	timer, c := newFakeTimer()
	timer.Start()
	c.advance(3)
	invocation := timer.InvokeStart()
	c.advance(7)
	timer.FirstByte(invocation)
	if got := timer.Snapshot().TTFBMS; got != 7 {
		t.Fatalf("incremental TTFB=%d", got)
	}
	c.advance(11)
	elapsed := timer.End()
	before := timer.Snapshot()
	if before.UpstreamMS != 18 || before.UpstreamPartial != 1 || before.TTFBMS != 7 {
		t.Fatalf("partial=%+v", before)
	}
	assertPhaseSum(t, timer, elapsed)
	c.advance(100)
	done := make(chan struct{})
	go func() { timer.InvokeComplete(invocation); close(done) }()
	<-done
	if after := timer.Snapshot(); after != before {
		t.Fatalf("late completion changed frozen fields: %+v -> %+v", before, after)
	}
}

func TestPhaseTimerMultipleInvocationsAndSettlements(t *testing.T) {
	timer, c := newFakeTimer()
	timer.Start()
	invocation := timer.InvokeStart()
	c.advance(10)
	timer.FirstByte(invocation)
	timer.InvokeComplete(invocation)
	start := c.Now()
	c.advance(20)
	timer.SettleDone(start, "ok")
	invocation = timer.InvokeStart()
	c.advance(5)
	timer.FirstByte(invocation)
	c.advance(5)
	timer.InvokeComplete(invocation)
	start = c.Now()
	c.advance(3)
	timer.SettleDone(start, "deferred")
	c.advance(7)
	elapsed := timer.End()
	f := timer.Snapshot()
	if f.UpstreamMS != 20 || f.TTFBMS != 10 || f.SettleMS != 23 || f.ReceiptMS != 7 || f.SettleOutcome != "deferred" {
		t.Fatalf("multiple invocations=%+v", f)
	}
	assertPhaseSum(t, timer, elapsed)
}

func TestPhaseTimerSettlementSpansCompletion(t *testing.T) {
	timer, c := newFakeTimer()
	timer.Start()
	invocation := timer.InvokeStart()
	c.advance(5)
	start := c.Now()
	c.advance(5)
	timer.InvokeComplete(invocation)
	c.advance(3)
	timer.SettleDone(start, "ok")
	c.advance(7)
	elapsed := timer.End()
	assertPhaseSum(t, timer, elapsed)
	if f := timer.Snapshot(); f.UpstreamMS != 10 || f.ReceiptMS != 7 || f.SettleMS != 3 {
		t.Fatalf("overlapping settlement=%+v", f)
	}
}

// A runs 0–30 and produces a byte at 20; B starts at 10 and remains active
// through End=40. Completing A must not clear B or reset A's TTFB origin.
func TestPhaseTimerOverlappingInvocations(t *testing.T) {
	timer, c := newFakeTimer()
	timer.Start()
	a := timer.InvokeStart()
	c.advance(10)
	b := timer.InvokeStart()
	c.advance(10)
	timer.FirstByte(a)
	c.advance(10)
	timer.InvokeComplete(a)
	c.advance(10)
	elapsed := timer.End()
	before := timer.Snapshot()
	if before.UpstreamMS != 40 || before.TTFBMS != 20 || before.UpstreamPartial != 1 || before.ReceiptMS != 0 {
		t.Fatalf("overlapping invocations=%+v", before)
	}
	assertPhaseSum(t, timer, elapsed)
	c.advance(100)
	timer.FirstByte(b)
	timer.InvokeComplete(b)
	timer.InvokeComplete(a)
	timer.InvokeStart()
	timer.RetryWaitDone(c.Now().Add(-time.Second))
	timer.SettleDone(c.Now().Add(-time.Second), "failed")
	if after := timer.Snapshot(); after != before || timer.End() != elapsed {
		t.Fatalf("late work changed frozen fields: %+v -> %+v", before, after)
	}
}

func TestPhaseTimerCompletedInvocationUnion(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "start_order", true: "reverse_order"}[reverse], func(t *testing.T) {
			timer, c := newFakeTimer()
			timer.Start()
			a := timer.InvokeStart()
			c.advance(10)
			b := timer.InvokeStart()
			c.advance(5)
			// B produces a byte first, even though A started first.
			timer.FirstByte(b)
			c.advance(5)
			timer.FirstByte(a)
			if reverse {
				timer.InvokeComplete(b)
			} else {
				timer.InvokeComplete(a)
			}
			c.advance(10)
			timer.InvokeComplete(a)
			timer.InvokeComplete(b)
			c.advance(5)
			elapsed := timer.End()
			f := timer.Snapshot()
			if f.UpstreamMS != 30 || f.UpstreamPartial != 0 || f.TTFBMS != 5 || f.ReceiptMS != 5 {
				t.Fatalf("completed union=%+v", f)
			}
			assertPhaseSum(t, timer, elapsed)
		})
	}
}

func TestPhaseTimerPartialSettlementOverlap(t *testing.T) {
	timer, c := newFakeTimer()
	timer.Start()
	timer.InvokeStart()
	c.advance(10)
	start := c.Now()
	c.advance(10)
	timer.SettleDone(start, "ok")
	c.advance(10)
	elapsed := timer.End()
	f := timer.Snapshot()
	if f.UpstreamMS != 30 || f.UpstreamPartial != 1 || f.SettleMS != 0 || f.SettleOutcome != "ok" || f.ReceiptMS != 0 {
		t.Fatalf("partial settlement overlap=%+v", f)
	}
	assertPhaseSum(t, timer, elapsed)
}

func TestPhaseTimerOverlappingSettlements(t *testing.T) {
	timer, c := newFakeTimer()
	timer.Start()
	invocation := timer.InvokeStart()
	c.advance(5)
	first := c.Now()
	c.advance(5)
	timer.InvokeComplete(invocation)
	second := c.Now()
	c.advance(5)
	timer.SettleDone(first, "ok")
	c.advance(5)
	timer.SettleDone(second, "deferred")
	c.advance(5)
	elapsed := timer.End()
	f := timer.Snapshot()
	if f.UpstreamMS != 10 || f.SettleMS != 10 || f.ReceiptMS != 5 {
		t.Fatalf("settlement union=%+v", f)
	}
	assertPhaseSum(t, timer, elapsed)
}

func TestPhaseTimerRetryWaitAccumulatesActualDuration(t *testing.T) {
	timer, c := newFakeTimer()
	timer.Start()
	for i := 0; i < 3; i++ {
		invocation := timer.InvokeStart()
		c.advance(100)
		timer.InvokeComplete(invocation)
		if i < 2 {
			start := c.Now()
			c.advance(int64(i+1) * 1000)
			timer.RetryWaitDone(start)
		}
	}
	elapsed := timer.End()
	f := timer.Snapshot()
	if f.UpstreamMS != 300 || f.RetryWaitMS != 3000 || f.RouteMS != 0 || f.ReceiptMS != 0 || elapsed != 3300*time.Millisecond {
		t.Fatalf("retry waits=%+v elapsed=%s", f, elapsed)
	}
	assertPhaseSum(t, timer, elapsed)
}
