package shadowcoord

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func reviewSigned(t *testing.T, c *Coordinator, f wireFixture, iat, start int64, name string) Refresh {
	t.Helper()
	base := repairedGrant(t, c, f, 0, 0)
	results, _ := base(t.Context(), f.Items)
	parts := strings.Split(results[0].Grant, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	claims := ParseRequest(payload)
	claims["iat"] = iat
	claims["exp"] = iat + 30
	claims["start_before"] = start
	claims["grant_id"] = name
	h := claims["history"].(map[string]any)
	h["last_success_at"] = iat
	h["window_start"] = iat - 600
	payload, _ = json.Marshal(claims)
	msg := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	grant := msg + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(make([]byte, 32)), []byte(msg)))
	return func(context.Context, []Identity) ([]Result, *Miss) {
		return []Result{{Identity: f.Items[0], Grant: grant}}, nil
	}
}
func TestReviewR4WatermarkLegitimateOlder(t *testing.T) {
	for _, iat := range []int64{1999, 2000} {
		c, clock, req, _, f := setup(t)
		c.ObserveAuthorized(f.Items[0])
		c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2000, 2001, "short"))
		clock.add(time.Second)
		c.RefreshOnce(t.Context(), reviewSigned(t, c, f, iat, iat+28, "legitimate-older"))
		requireDecision(t, c, f, req, "grant-replay")
		t.Logf("iat=%d, wall=%d, watermark=%d: otherwise valid grant rejected", iat, clock.Now().Unix(), c.entries[f.Items[0]].receiptWatermark)
		c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2001, 2029, "new"))
		requireDecision(t, c, f, req, "eligible")
	}
}
func TestReviewR4SameSecondRegeneration(t *testing.T) {
	c, clock, req, _, f := setup(t)
	c.config.ClockUncertainty = 500 * time.Millisecond
	c.ObserveAuthorized(f.Items[0])
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2000, 2001, "short"))
	clock.add(600 * time.Millisecond)
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2000, 2028, "regenerated"))
	requireDecision(t, c, f, req, "grant-replay")
	clock.add(400 * time.Millisecond)
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2001, 2029, "next-second"))
	requireDecision(t, c, f, req, "eligible")
	t.Log("same-second refresh rejected at 600ms; next issuance second restores eligibility at 1s")
}
func TestReviewR4LiveReceiptBelowWatermark(t *testing.T) {
	c, clock, req, _, f := setup(t)
	c.ObserveAuthorized(f.Items[0])
	old := reviewSigned(t, c, f, 2000, 2028, "live-old")
	c.RefreshOnce(t.Context(), old)
	clock.add(time.Second)
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2001, 2002, "short-new"))
	clock.add(time.Second)
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2002, 2030, "newest"))
	c.RefreshOnce(t.Context(), old)
	requireDecision(t, c, f, req, "eligible")
	if c.entries[f.Items[0]].cached.startDeadline != 28*time.Second {
		t.Fatal("original deadline changed")
	}
	t.Log("live iat=2000 accepted beneath watermark=2001 with unchanged 28s deadline")
}
func TestReviewR4DelayedRefreshRetirement(t *testing.T) {
	c, clock, req, _, f := setup(t)
	c.ObserveAuthorized(f.Items[0])
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2000, 2001, "short"))
	delayed := reviewSigned(t, c, f, 2000, 2028, "delayed")
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		c.RefreshOnce(t.Context(), func(ctx context.Context, ids []Identity) ([]Result, *Miss) {
			close(entered)
			<-release
			return delayed(ctx, ids)
		})
	}()
	<-entered
	clock.add(time.Second)
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2001, 2029, "newer"))
	close(release)
	<-done
	requireDecision(t, c, f, req, "grant-replay")
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2001, 2029, "newer-again"))
	requireDecision(t, c, f, req, "eligible")
	t.Log("delayed older response is rejected after retirement and clears newer cache; next fresh refresh heals")
}
func TestReviewR4FlappingBoot(t *testing.T) {
	c, clock, _, r, f := setup(t)
	warm(c, f, r)
	c.ObserveVerdict("", 503, "infrastructure_error", "")
	for range 20 {
		c.ObserveAuthorized(f.Items[0])
		clock.add(10 * time.Second)
		c.ObserveAuthorized(f.Items[0])
		clock.add(10 * time.Second)
		c.ObserveVerdict(strings.Repeat("b", 64), 503, "infrastructure_error", "")
		if !c.bootClosed || c.bootBreaker.successes != 0 {
			t.Fatal("flapping boot reopened")
		}
	}
	t.Log("400 seconds of one-key failure every 20s keeps the boot closed despite healthy-key probes")
	c.ObserveAuthorized(f.Items[0])
	clock.add(15 * time.Second)
	c.ObserveAuthorized(f.Items[0])
	clock.add(15 * time.Second)
	c.ObserveAuthorized(f.Items[0])
	c.entries[f.Items[0]].evidenceDeadline = clock.Now().Add(time.Hour)
	extendFixture(&f, clock.Now().Unix())
	c.entries[f.Items[0]].evidence.Local.Bindings["route"] = f.Context["route"]
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
	if c.bootClosed {
		t.Fatal("clean interval failed to heal boot")
	}
}
func TestReviewR4EmptyJournalKeepsWatermark(t *testing.T) {
	original, _, req, _, f := setup(t)
	start := time.Now()
	start = start.Add(time.Unix(2000, 0).Sub(start))
	clock := &fakeClock{now: start}
	c := New(Shadow, original.config, clock)
	c.ObserveAuthorized(f.Items[0])
	first := reviewSigned(t, c, f, 2000, 2001, "first")
	c.RefreshOnce(t.Context(), first)
	clock.add(time.Second)
	clock.now = reviewWallShift(clock.now, -1)
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2000, 2028, "other-same-second"))
	requireDecision(t, c, f, req, "grant-replay")
	s := c.entries[f.Items[0]]
	if len(s.receipts) != 0 || !s.receiptsRetired || s.receiptWatermark != 2000 {
		t.Fatal("did not empty journal")
	}
	c.RefreshOnce(t.Context(), first)
	requireDecision(t, c, f, req, "grant-replay")
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 1999, 2027, "older"))
	requireDecision(t, c, f, req, "grant-replay")
	clock.add(time.Second)
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2001, 2029, "new"))
	requireDecision(t, c, f, req, "eligible")
	t.Log("watermark remains 2000 through empty journal and clock rollback; retired fingerprint and older fresh JWS rejected")
}
func TestReviewR4RollbackStarvationHeals(t *testing.T) {
	original, _, req, _, f := setup(t)
	start := time.Now()
	start = start.Add(time.Unix(2000, 0).Sub(start))
	clock := &fakeClock{now: start}
	c := New(Shadow, original.config, clock)
	c.ObserveAuthorized(f.Items[0])
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2000, 2001, "short"))
	clock.add(time.Second)
	clock.now = reviewWallShift(clock.now, -20)
	for i := 0; i < 20; i++ {
		iat := clock.Now().Unix()
		c.RefreshOnce(t.Context(), reviewSigned(t, c, f, iat, iat+28, "rolled-back"))
		requireDecision(t, c, f, req, "grant-replay")
		clock.add(time.Second)
	}
	c.RefreshOnce(t.Context(), reviewSigned(t, c, f, 2001, 2029, "healed"))
	requireDecision(t, c, f, req, "eligible")
	t.Log("20s rollback causes 20s of valid fresh grant rejections, then heals when iat crosses 2000")
}
func TestReviewR4StillLiveNearRetirement(t *testing.T) {
	c, clock, req, _, f := setup(t)
	c.ObserveAuthorized(f.Items[0])
	first := reviewSigned(t, c, f, 2000, 2028, "first")
	c.RefreshOnce(t.Context(), first)
	clock.add(27500 * time.Millisecond)
	c.RefreshOnce(t.Context(), first)
	c.RefreshOnce(t.Context(), first)
	requireDecision(t, c, f, req, "eligible")
}
func TestReviewR4BootResetRejectsOldSuccess(t *testing.T) {
	c, clock, _, r, f := setup(t)
	warm(c, f, r)
	c.ObserveVerdict("", 503, "infrastructure_error", "")
	old := c.ObservationVersion()
	clock.add(time.Second)
	c.ObserveVerdict(strings.Repeat("b", 64), 503, "infrastructure_error", "")
	c.ObserveAuthorizedSince(f.Items[0], old)
	if c.bootBreaker.successes != 0 {
		t.Fatal("pre-latest-failure callback counted toward boot recovery")
	}
}
func TestReviewR4EvictionCannotRestartReceipts(t *testing.T) {
	original, _, req, _, f := setup(t)
	start := time.Now()
	start = start.Add(time.Unix(2000, 0).Sub(start))
	clock := &fakeClock{now: start}
	c := New(Shadow, original.config, clock)
	c.ObserveAuthorized(f.Items[0])
	old := reviewSigned(t, c, f, 2000, 2028, "old")
	c.RefreshOnce(t.Context(), old)
	clock.add(101 * time.Second)
	c.mu.Lock()
	evicted := c.evictExpired()
	c.mu.Unlock()
	if !evicted {
		t.Fatal("not evicted")
	}
	c.ObserveAuthorized(f.Items[0])
	clock.now = reviewWallShift(clock.now, -101)
	c.RefreshOnce(t.Context(), old)
	requireDecision(t, c, f, req, "policy-stale")
	t.Log("evict, relearn, roll back to original issuance: no replacement policy, replay rejected policy-stale")
}
func TestReviewR4OffConstructorAllocation(t *testing.T) {
	if n := testing.AllocsPerRun(1000, func() {
		if New(Off, Config{}, nil) != nil {
			panic("unexpected coordinator")
		}
	}); n != 0 {
		t.Fatalf("off allocations=%v", n)
	}
}
