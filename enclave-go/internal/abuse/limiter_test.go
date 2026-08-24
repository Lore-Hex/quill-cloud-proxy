package abuse

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestLimiterCountsOnlyFailuresAndRefillsAtTenPerMinute(t *testing.T) {
	limiter := NewLimiter(10, 30, 100)
	now := time.Unix(1_700_000_000, 0)
	for range 1_000 {
		if ok, _ := limiter.Allow("192.0.2.10", now); !ok {
			t.Fatal("an allowed or valid request drained the failure bucket")
		}
	}
	if got := limiter.Len(); got != 0 {
		t.Fatalf("valid-only occupancy = %d, want 0", got)
	}
	for range 30 {
		if ok, _ := limiter.Allow("192.0.2.10", now); !ok {
			t.Fatal("burst rejected before 30 failed authentications")
		}
		limiter.RecordFailure("192.0.2.10", now)
	}
	if ok, _ := limiter.Allow("192.0.2.10", now); ok {
		t.Fatal("31st immediate attempt was allowed")
	}
	if ok, _ := limiter.Allow("192.0.2.10", now.Add(6*time.Second)); !ok {
		t.Fatal("sustained budget did not refill at ten failures per minute")
	}
}

func TestLimiterLRUBoundHoldsUnderSourceSpray(t *testing.T) {
	limiter := NewLimiter(10, 30, 3)
	now := time.Unix(1_700_000_000, 0)
	for index := 0; index < 10_000; index++ {
		limiter.RecordFailure(fmt.Sprintf("2001:db8::%x", index), now)
	}
	if got := limiter.Len(); got != 3 {
		t.Fatalf("bucket occupancy = %d, want 3", got)
	}
}

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

func TestWithDirectClientIPUsesRemoteAddrWithoutForwardedHeaderSurface(t *testing.T) {
	state := &RequestState{}
	ctx := WithRequestState(t.Context(), state)
	ctx = WithDirectClientIP(ctx, testAddr(net.JoinHostPort("2001:db8::7", "44321")))
	if got := clientIP(ctx); got != "2001:db8::7" {
		t.Fatalf("client IP = %q, want direct RemoteAddr host", got)
	}
}

func TestWithDirectClientIPRefusesNonIPTransportPeers(t *testing.T) {
	ctx := WithDirectClientIP(t.Context(), testAddr("host(3):49152"))
	if got := clientIP(ctx); got != "" {
		t.Fatalf("non-IP transport became limiter source %q", got)
	}
}

func TestDenyReturnsHonestRetryAfter(t *testing.T) {
	now := time.Now()
	limiter := NewLimiter(10, 1, 8) // 10/min => one token every 6s
	limiter.RecordFailure("192.0.2.99", now)
	ok, retry := limiter.Allow("192.0.2.99", now)
	if ok {
		t.Fatal("expected deny after burst exhausted")
	}
	// One token refills in 6s; the estimate must land there, not at zero and
	// not at the full window. Allow slack for float arithmetic.
	if retry < 5*time.Second || retry > 7*time.Second {
		t.Fatalf("retryAfter = %v, want ~6s", retry)
	}
}
