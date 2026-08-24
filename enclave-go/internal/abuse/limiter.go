// Package abuse contains bounded, in-enclave controls for failed credential
// probes. It deliberately trusts only the socket's RemoteAddr; no component in
// front of the enclave sets a trustworthy forwarding header.
package abuse

import (
	"container/list"
	"sync"
	"time"
)

const (
	// DefaultFailuresPerMinute lets a typoing client fail about once every six
	// seconds indefinitely while making a tight invalid-key loop expensive.
	DefaultFailuresPerMinute = 10.0
	// DefaultBurst absorbs SDK retries and ordinary copy/paste mistakes before
	// the sustained failed-auth budget becomes visible to the caller.
	DefaultBurst = 30
	// DefaultMaxSources bounds attacker-controlled source state to the same
	// predictable ceiling as the negative credential cache.
	DefaultMaxSources = 65_536
)

type bucket struct {
	source     string
	tokens     float64
	lastRefill time.Time
}

// Limiter is a token bucket per direct client IP with an LRU-bounded table.
// Looking up an unseen source never allocates: only an observed authentication
// failure creates state, so successful paid traffic does not fill the table.
type Limiter struct {
	mu              sync.Mutex
	tokensPerSecond float64
	burst           float64
	maxSources      int
	buckets         map[string]*list.Element
	lru             *list.List
}

func NewLimiter(failuresPerMinute float64, burst, maxSources int) *Limiter {
	if failuresPerMinute <= 0 {
		failuresPerMinute = DefaultFailuresPerMinute
	}
	if burst <= 0 {
		burst = DefaultBurst
	}
	if maxSources <= 0 {
		maxSources = DefaultMaxSources
	}
	return &Limiter{
		tokensPerSecond: failuresPerMinute / 60,
		burst:           float64(burst),
		maxSources:      maxSources,
		buckets:         make(map[string]*list.Element, maxSources),
		lru:             list.New(),
	}
}

// Allow reports whether a credential-bearing request may reach the control
// plane. It only peeks: a token is consumed later and only if auth definitively
// fails, so valid paid traffic never increments or drains the limiter.
//
// On deny, retryAfter is how long until one token has refilled -- the honest
// Retry-After for the 429, computed from the same bucket state that made the
// decision rather than a second lookup that can disagree with it.
func (l *Limiter) Allow(source string, now time.Time) (allowed bool, retryAfter time.Duration) {
	if l == nil || source == "" {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	element, ok := l.buckets[source]
	if !ok {
		return true, 0
	}
	item := element.Value.(*bucket)
	l.refill(item, now)
	l.lru.MoveToFront(element)
	if item.tokens >= 1 {
		return true, 0
	}
	deficit := 1 - item.tokens
	return false, time.Duration(deficit / l.tokensPerSecond * float64(time.Second))
}

// RecordFailure consumes one token after a definitive invalid-credential
// verdict (including a negative-cache hit). Concurrent in-flight failures may
// exhaust the bucket together, after which new requests are rejected cheaply.
func (l *Limiter) RecordFailure(source string, now time.Time) {
	if l == nil || source == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if element, ok := l.buckets[source]; ok {
		item := element.Value.(*bucket)
		l.refill(item, now)
		item.tokens = max(0, item.tokens-1)
		l.lru.MoveToFront(element)
		return
	}
	for len(l.buckets) >= l.maxSources {
		l.remove(l.lru.Back())
	}
	item := &bucket{source: source, tokens: l.burst - 1, lastRefill: now}
	element := l.lru.PushFront(item)
	l.buckets[source] = element
}

func (l *Limiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func (l *Limiter) refill(item *bucket, now time.Time) {
	if !now.After(item.lastRefill) {
		return
	}
	item.tokens = min(l.burst, item.tokens+now.Sub(item.lastRefill).Seconds()*l.tokensPerSecond)
	item.lastRefill = now
}

func (l *Limiter) remove(element *list.Element) {
	if element == nil {
		return
	}
	item := element.Value.(*bucket)
	delete(l.buckets, item.source)
	l.lru.Remove(element)
}
