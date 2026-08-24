package abuse

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/authcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

const (
	OutcomeCachedReject = "auth_cached_reject"
	OutcomeRateLimited  = "auth_rate_limited"
)

type clientIPContextKey struct{}
type requestStateContextKey struct{}

// RequestState carries content-free abuse disposition across the nested auth
// calls made by one public request. It also prevents the audit fallback from
// counting or relabeling the same failed credential a second time.
type RequestState struct {
	mu                 sync.Mutex
	outcome            string
	definitiveRejected bool
}

// WithDirectClientIP records only RemoteAddr. X-Forwarded-For is deliberately
// absent: no trusted hop sets it, so accepting it would give an attacker an
// unlimited supply of spoofed limiter buckets.
func WithDirectClientIP(ctx context.Context, address net.Addr) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if address == nil {
		return ctx
	}
	value := address.String()
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	parsed := net.ParseIP(value)
	if parsed == nil {
		return ctx
	}
	return context.WithValue(ctx, clientIPContextKey{}, parsed.String())
}

func WithRequestState(ctx context.Context, state *RequestState) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if state == nil {
		return ctx
	}
	return context.WithValue(ctx, requestStateContextKey{}, state)
}

func Outcome(ctx context.Context) string {
	state := requestState(ctx)
	if state == nil {
		return ""
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.outcome
}

func clientIP(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(clientIPContextKey{}).(string)
	return value
}

func requestState(ctx context.Context) *RequestState {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(requestStateContextKey{}).(*RequestState)
	return state
}

func markOutcome(ctx context.Context, outcome string) {
	state := requestState(ctx)
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.outcome = outcome
}

func markDefinitiveRejected(ctx context.Context) {
	state := requestState(ctx)
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.definitiveRejected = true
}

func priorRequestRejection(ctx context.Context) (outcome string, definitive bool) {
	state := requestState(ctx)
	if state == nil {
		return "", false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.outcome, state.definitiveRejected
}

type Stats struct {
	NegativeCacheHits  uint64
	RateLimitedRejects uint64
	BucketOccupancy    int
	CacheOccupancy     int
}

// Protector composes the negative verdict cache and failed-auth token buckets.
// It implements trustedrouter.CredentialGuard and is safe for concurrent calls.
type Protector struct {
	cache       *authcache.Cache
	limiter     *Limiter
	now         func() time.Time
	cacheHits   atomic.Uint64
	rateRejects atomic.Uint64
}

func NewProtector(cache *authcache.Cache, limiter *Limiter) *Protector {
	if cache == nil {
		cache = authcache.New(authcache.DefaultTTL, authcache.DefaultMaxEntries)
	}
	if limiter == nil {
		limiter = NewLimiter(DefaultFailuresPerMinute, DefaultBurst, DefaultMaxSources)
	}
	return &Protector{cache: cache, limiter: limiter, now: time.Now}
}

func (p *Protector) BeforeCredentialCheck(ctx context.Context, lookupHash string) error {
	if p == nil {
		return nil
	}
	if outcome, definitive := priorRequestRejection(ctx); outcome != "" {
		return rejectionError(outcome)
	} else if definitive {
		return definitiveRejectionError()
	}
	source := clientIP(ctx)
	now := p.now()
	// Internal batch execution has no public socket source. It still benefits
	// from definitive negative caching and normal revocation checks, but cannot
	// be charged to a caller IP bucket.
	allowed, retryAfter := p.limiter.Allow(source, now)
	if source != "" && !allowed {
		p.rateRejects.Add(1)
		markOutcome(ctx, OutcomeRateLimited)
		return rateLimitedError(retryAfter)
	}
	if p.cache.Contains(lookupHash, now) {
		p.cacheHits.Add(1)
		p.limiter.RecordFailure(source, now)
		markOutcome(ctx, OutcomeCachedReject)
		return rejectionError(OutcomeCachedReject)
	}
	return nil
}

func (p *Protector) AfterCredentialCheck(ctx context.Context, lookupHash string, err error) {
	if p == nil {
		return
	}
	now := p.now()
	if !p.cache.Remember(lookupHash, err, now) {
		return
	}
	p.limiter.RecordFailure(clientIP(ctx), now)
	markDefinitiveRejected(ctx)
}

func (p *Protector) Stats() Stats {
	if p == nil {
		return Stats{}
	}
	return Stats{
		NegativeCacheHits:  p.cacheHits.Load(),
		RateLimitedRejects: p.rateRejects.Load(),
		BucketOccupancy:    p.limiter.Len(),
		CacheOccupancy:     p.cache.Len(),
	}
}

// StartStats emits cumulative counters plus bounded-table occupancy. Silent
// controls rot; this line makes both an attack and state pressure visible.
func (p *Protector) StartStats(ctx context.Context, w io.Writer, interval time.Duration) {
	if p == nil || w == nil {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := p.Stats()
				fmt.Fprintf(w,
					"enclave.abuse_stats negative_cache_hits=%d rate_limited_rejects=%d bucket_occupancy=%d cache_occupancy=%d\n",
					stats.NegativeCacheHits,
					stats.RateLimitedRejects,
					stats.BucketOccupancy,
					stats.CacheOccupancy,
				)
			}
		}
	}()
}

func rejectionError(outcome string) error {
	switch outcome {
	case OutcomeCachedReject:
		return &trustedrouter.ControlPlaneError{
			StatusCode: http.StatusUnauthorized,
			Type:       OutcomeCachedReject,
			Message:    "Invalid API key",
		}
	case OutcomeRateLimited:
		// A replayed rejection from earlier in this request's life carries no
		// bucket state; one second is the honest floor.
		return rateLimitedError(time.Second)
	default:
		return nil
	}
}

// rateLimitedError carries Retry-After from the SAME bucket computation that
// denied the request (RFC 9110 delta-seconds; the standard self-throttle
// signal for agents). WriteErrorWithSourceHeaders already emits
// ControlPlaneError.RetryAfter as the header, so setting the field is the
// whole wire story.
func rateLimitedError(retryAfter time.Duration) error {
	seconds := int(math.Ceil(retryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	return &trustedrouter.ControlPlaneError{
		StatusCode: http.StatusTooManyRequests,
		Type:       OutcomeRateLimited,
		Message:    "Too many failed authentication attempts",
		RetryAfter: strconv.Itoa(seconds),
	}
}

func definitiveRejectionError() error {
	return &trustedrouter.ControlPlaneError{
		StatusCode: http.StatusUnauthorized,
		Type:       "invalid_api_key",
		Message:    "Invalid API key",
	}
}
