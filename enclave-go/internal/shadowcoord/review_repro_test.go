package shadowcoord

import (
	"context"
	"testing"
	"time"
	"unsafe"
)

// Change only wall time; preserve the monotonic component as an NTP step does.
func reviewWallShift(v time.Time, seconds int64) time.Time {
	type representation struct {
		wall uint64
		ext  int64
		loc  *time.Location
	}
	p := (*representation)(unsafe.Pointer(&v))
	if p.wall>>63 != 1 {
		panic("test time has no monotonic component")
	}
	sec := int64((p.wall>>30)&((1<<33)-1)) + seconds // #nosec G115 -- masked to 33 bits.
	if sec < 0 || sec >= 1<<33 {
		panic("test wall shift outside monotonic representation")
	}
	p.wall = (1 << 63) | (uint64(sec) << 30) | (p.wall & ((1 << 30) - 1))
	return v
}
func TestReviewReplayAfterMissCannotRenewMonotonicDeadline(t *testing.T) {
	original, _, req, r, f := setup(t)
	start := time.Now()
	start = start.Add(time.Unix(2000, 0).Sub(start))
	clock := &fakeClock{now: start}
	c := New(Shadow, original.config, clock)
	warm(c, f, r)
	clock.add(10 * time.Second)
	c.RefreshOnce(context.Background(), func(context.Context, []Identity) ([]Result, *Miss) {
		return nil, &Miss{Status: 503, Code: "refresh-rate-limited"}
	})
	clock.add(21 * time.Second)
	clock.now = reviewWallShift(clock.now, -21)
	if c.Mono() != 31*time.Second || clock.Now().Unix() != 2010 {
		t.Fatal("invalid test clock", c.Mono(), clock.Now())
	}
	c.RefreshOnce(context.Background(), r)
	d := c.Predecision(f.Items[0].LookupDigest, req).Decision()
	if d.Eligible {
		t.Fatalf("replayed grant eligible at monotonic %v, wall=%d, original grant deadline=28s/history deadline=20s: %+v", c.Mono(), clock.Now().Unix(), d)
	}
}
func TestReviewFinishReleasesUnstartedAdmission(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	x := c.Predecision(f.Items[0].LookupDigest, req)
	if !x.Decision().Eligible {
		t.Fatal(x.Decision())
	}
	// Ordinary AuthorizeWithRoute can return from its second credential guard
	// before reaching observeShadowAuthorize. The handler still calls Finish.
	x.Finish()
	d := c.Predecision(f.Items[0].LookupDigest, req).Decision()
	if d.Reason == "simulated-concurrency" {
		t.Fatalf("finished request permanently owns unresolved slot: %+v", d)
	}
}
func TestReviewNoWaitOnRefreshNetwork(t *testing.T) {
	c, _, req, _, f := setup(t)
	c.ObserveAuthorized(f.Items[0])
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		c.RefreshOnce(t.Context(), func(context.Context, []Identity) ([]Result, *Miss) {
			close(entered)
			<-release
			return nil, &Miss{Code: "slow"}
		})
		close(done)
	}()
	<-entered
	start := time.Now()
	d := c.Predecision(f.Items[0].LookupDigest, req).Decision()
	elapsed := time.Since(start)
	close(release)
	<-done
	if d.Eligible || elapsed > 100*time.Millisecond {
		t.Fatal(d, elapsed)
	}
}
func TestReviewUnresolvedWorkspaceDenialInvalidatesCoverage(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	// Another key may belong to w; no ordinary success has bound it locally yet.
	// The authenticated router returned an ambiguous billing 402 for that key.
	c.ObserveVerdict("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 402, "", "")
	d := c.Predecision(f.Items[0].LookupDigest, req).Decision()
	if d.Eligible {
		t.Fatalf("unknown workspace for local billing denial silently ignored; cached key remains eligible: %+v", d)
	}
}
