// Package requesttiming records content-free, request-scoped phase timings.
//
// Upstream is the wall-clock union of all invocation intervals, including the
// elapsed portion of every still-active invocation at End. It is not cumulative
// provider work. TTFB belongs to the invocation that first reports a byte and is
// measured from that invocation's start; subsequent invocations cannot reset it.
// Settlement is the union of completed settlement intervals outside upstream:
// overlapping settle+invoke time is counted once, in upstream. Receipt is the
// tail after the last invocation completes, excluding settlement in that tail.
// If any invocation is active at End, upstream_partial is 1 (even for a normally
// delivered stream), those invocations extend through End, and receipt is zero.
// End freezes every field; detached completions cannot revise the snapshot.
//
// Idle wait runs from timer creation to the first request byte on a reused,
// unbuffered connection. First requests and already-buffered requests use timer
// creation as their request origin (zero idle wait). Thus lazy TLS handshakes
// on first requests remain in accept_to_start and request. Request runs from
// that origin through End; elapsed retains timer creation through End. If a
// reused connection ends before any byte arrives and without Start, all elapsed
// time is idle and request is zero. If Start occurs while still waiting for a
// byte, the request origin falls back to timer creation and idle wait is zero;
// request and accept_to_start are both measured from creation in that case.
// Latency dashboards should use request_ms, not elapsed_ms.
//
// Before millisecond truncation, accept_to_start + authorize + route + upstream
// + retry_wait + settle + receipt = request when Start and an invocation occur,
// Start precedes the first invocation,
// authorization is non-overlapping and wholly between Start and first invoke,
// completed retry waits do not overlap each other or another measured phase,
// settlements do not overlap pre-invocation phases or retry waits, and every gap
// between invocations is covered by a retry wait or settlement. The identity
// also holds for partial invocations under these conditions. It is not a general
// invariant for rejected requests, concurrent authorization/retry work, waits
// still in progress at End, or uninstrumented gaps between orchestration calls.
// Authorize and retry_wait are cumulative durations, not unions. Each duration
// is truncated for reporting, so logged phase sums can be below request_ms
// by less than one millisecond per summed field.
package requesttiming

import (
	"context"
	"net/url"
	"slices"
	"sync"
	"time"
)

type contextKey struct{}

// Fields is an immutable snapshot. Durations are truncated to milliseconds
// after accumulation, rather than rounding each control-plane attempt.
type Fields struct {
	IdleWaitMS, RequestMS                                                int64
	AcceptToStartMS, AuthorizeMS, RouteMS, UpstreamMS, TTFBMS            int64
	RetryWaitMS, SettleMS, ReceiptMS, AuthorizeAttempts, UpstreamPartial int64
	SettleOutcome, CPEndpoint                                            string
}

// Timer defaults to time.Now's monotonic clock. Provider completion and
// speculative authorization can run on different goroutines. Snapshot never
// advances a phase; End freezes the request before detached work can change it.
type Timer struct {
	mu                                                  sync.Mutex
	now                                                 func() time.Time
	active                                              map[*Invocation]struct{}
	hasFirstByte                                        bool
	invocations                                         []interval
	settlements                                         []interval
	upstream                                            time.Duration
	upstreamPartial                                     int64
	accepted, requestByte, started, completed           time.Time
	acceptToStart, authorize, route, retryWait, receipt time.Duration
	ttfbMS, attempts                                    int64
	endpoint, outcome                                   string
	invoked, ended                                      bool
	elapsed, idleWait, request                          time.Duration
	waitingForByte                                      bool
}

// Invocation is an opaque, request-local token. Each concurrent provider
// attempt must retain its own token for FirstByte and InvokeComplete.
type Invocation struct{ start time.Time }

type interval struct{ start, end time.Time }

// addInterval maintains a sorted wall-clock union, including out-of-order
// completions from concurrent invocations and settlements.
func addInterval(intervals []interval, next interval) []interval {
	intervals = append(intervals, next)
	slices.SortFunc(intervals, func(a, b interval) int { return a.start.Compare(b.start) })
	merged := intervals[:0]
	for _, current := range intervals {
		if len(merged) == 0 || current.start.After(merged[len(merged)-1].end) {
			merged = append(merged, current)
		} else if current.end.After(merged[len(merged)-1].end) {
			merged[len(merged)-1].end = current.end
		}
	}
	return merged
}

func duration(intervals []interval) time.Duration {
	var total time.Duration
	for _, current := range intervals {
		total += current.end.Sub(current.start)
	}
	return total
}

// overlapDuration requires each input to contain disjoint intervals.
func overlapDuration(a, b []interval) time.Duration {
	var total time.Duration
	for _, left := range a {
		for _, right := range b {
			start, end := left.start, left.end
			if right.start.After(start) {
				start = right.start
			}
			if right.end.Before(end) {
				end = right.end
			}
			total += max(0, end.Sub(start))
		}
	}
	return total
}

// New uses the supplied clock when non-nil, otherwise time.Now. The clock must
// be safe for concurrent calls and share accepted's time base.
func New(accepted time.Time, now func() time.Time) *Timer {
	if now == nil {
		now = time.Now
	}
	return &Timer{accepted: accepted, requestByte: accepted, now: now, outcome: "skipped", active: make(map[*Invocation]struct{})}
}

// Now samples the timing clock; a missing context timer uses the default clock.
func (t *Timer) Now() time.Time {
	if t == nil {
		return time.Now()
	}
	return t.now()
}

func WithTimer(ctx context.Context, timer *Timer) context.Context {
	return context.WithValue(ctx, contextKey{}, timer)
}

func FromContext(ctx context.Context) *Timer {
	timer, _ := ctx.Value(contextKey{}).(*Timer)
	return timer
}

// WaitForRequestByte separates idle time only for reused, unbuffered connections.
// Call before reading; the existing read path must call RequestFirstByte as
// soon as it returns data, without waiting for a complete request line.
func (t *Timer) WaitForRequestByte() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ended && t.started.IsZero() {
		t.waitingForByte = true
	}
}

// RequestFirstByte marks the request input boundary, distinct from a provider's
// FirstByte. Repeated marks and marks after Start or End are ignored.
func (t *Timer) RequestFirstByte() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended || !t.started.IsZero() || !t.waitingForByte {
		return
	}
	t.requestByte = t.Now()
	t.idleWait = t.requestByte.Sub(t.accepted)
	t.waitingForByte = false
}

func (t *Timer) Start() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended || !t.started.IsZero() {
		return
	}
	if t.waitingForByte {
		t.waitingForByte = false
		t.requestByte = t.accepted
		t.idleWait = 0
	}
	t.started = t.Now()
	t.acceptToStart = t.started.Sub(t.requestByte)
}

func (t *Timer) AuthorizeDone(start time.Time) {
	if t == nil {
		return
	}
	end := t.Now()
	duration := end.Sub(start)
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ended {
		t.authorize += duration
	}
}

// AuthorizeAttempt receives only the actual transport URL. Retain its hostname
// (no userinfo, port, path, query or fragment), bounded to a DNS hostname's size.
// With multiple authorities, the last attempted host is reported.
func (t *Timer) AuthorizeAttempt(endpoint string) {
	if t == nil {
		return
	}
	host := ""
	if u, err := url.Parse(endpoint); err == nil {
		host = u.Hostname()
		if len(host) > 253 {
			host = ""
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended {
		return
	}
	t.attempts++
	t.endpoint = host
}

// InvokeStart begins one provider attempt. The first attempt defines route time.
// The token also covers concurrent orchestration calls sharing this timer.
func (t *Timer) InvokeStart() *Invocation {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended {
		return nil
	}
	now := t.Now()
	if !t.invoked && !t.started.IsZero() {
		t.route = now.Sub(t.started)
	}
	t.invoked = true
	invocation := &Invocation{start: now}
	t.active[invocation] = struct{}{}
	return invocation
}

// FirstByte records the first reported byte before a write can block or the
// handler can return. The winning invocation's own start defines its TTFB.
func (t *Timer) FirstByte(invocation *Invocation) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, active := t.active[invocation]; t.ended || !active || t.hasFirstByte {
		return
	}
	t.ttfbMS = t.Now().Sub(invocation.start).Milliseconds()
	t.hasFirstByte = true
}

// InvokeComplete merges one provider attempt, including failures, into the
// wall-clock union. Unknown, duplicate and post-End completions are ignored.
func (t *Timer) InvokeComplete(invocation *Invocation) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, active := t.active[invocation]; t.ended || !active {
		return
	}
	t.completed = t.Now()
	t.invocations = addInterval(t.invocations, interval{invocation.start, t.completed})
	t.upstream = duration(t.invocations)
	delete(t.active, invocation)
}

// RetryWaitDone accumulates actual elapsed time around the existing retry sleep
// hook, not the requested sleep duration. A frozen timer ignores late returns.
func (t *Timer) RetryWaitDone(start time.Time) {
	if t == nil {
		return
	}
	end := t.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ended {
		t.retryWait += end.Sub(start)
	}
}

func (t *Timer) SettleDone(start time.Time, outcome string) {
	if t == nil {
		return
	}
	end := t.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended {
		return
	}
	t.settlements = addInterval(t.settlements, interval{start, end})
	t.outcome = outcome
}

func (t *Timer) End() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ended {
		end := t.Now()
		t.elapsed = end.Sub(t.accepted)
		if t.waitingForByte {
			t.idleWait = t.elapsed
		} else {
			t.request = end.Sub(t.requestByte)
		}
		if len(t.active) > 0 {
			for invocation := range t.active {
				t.invocations = addInterval(t.invocations, interval{invocation.start, end})
			}
			clear(t.active)
			t.upstream = duration(t.invocations)
			t.upstreamPartial = 1
		} else if !t.completed.IsZero() {
			tail := []interval{{t.completed, end}}
			t.receipt = end.Sub(t.completed) - overlapDuration(tail, t.settlements)
		}
		t.ended = true
	}
	return t.elapsed
}

func (t *Timer) Snapshot() Fields {
	if t == nil {
		return Fields{SettleOutcome: "skipped"}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return Fields{
		IdleWaitMS:        t.idleWait.Milliseconds(),
		RequestMS:         t.request.Milliseconds(),
		AcceptToStartMS:   t.acceptToStart.Milliseconds(),
		AuthorizeMS:       t.authorize.Milliseconds(),
		AuthorizeAttempts: t.attempts,
		RouteMS:           max(0, t.route-t.authorize).Milliseconds(),
		UpstreamMS:        t.upstream.Milliseconds(),
		UpstreamPartial:   t.upstreamPartial,
		TTFBMS:            t.ttfbMS,
		RetryWaitMS:       t.retryWait.Milliseconds(),
		SettleMS:          (duration(t.settlements) - overlapDuration(t.settlements, t.invocations)).Milliseconds(),
		SettleOutcome:     t.outcome,
		ReceiptMS:         t.receipt.Milliseconds(),
		CPEndpoint:        t.endpoint,
	}
}
