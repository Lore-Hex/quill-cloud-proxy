package shadowcoord

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

// The one-shot hook inserts a denial after receipt ordering is captured and
// before verification completes, without relying on scheduler timing.
type receiptClock struct {
	base Clock
	hook func()
}

func (c *receiptClock) Now() time.Time {
	if hook := c.hook; hook != nil {
		c.hook = nil
		hook()
	}
	return c.base.Now()
}
func TestReplayKeepsOriginalRecoveryOrder(t *testing.T) {
	for _, scope := range []string{"workspace", "key"} {
		t.Run(scope, func(t *testing.T) {
			c, clock, req, r, f := setup(t)
			warm(c, f, r)
			workspace, key := int64(1), int64(0)
			status, reason, want := 402, "credit_exhausted", "workspace_latched"
			if scope == "key" {
				workspace, key = 0, 1
				status, reason, want = 401, "key_invalid", "key_latched"
			}
			fresh := repairedGrant(t, c, f, workspace, key)
			results, _ := fresh(t.Context(), f.Items)
			c.clock = &receiptClock{base: clock, hook: func() { c.ObserveVerdict(f.Items[0].LookupDigest, status, reason, "") }}
			c.refreshResult(results[0])
			requireDecision(t, c, f, req, want)
			for range 3 {
				c.RefreshOnce(t.Context(), fresh)
				requireDecision(t, c, f, req, want)
			}
			clock.add(time.Second)
			c.RefreshOnce(t.Context(), repairedGrant(t, c, f, workspace+1, key+1))
			requireDecision(t, c, f, req, "eligible")
		})
	}
}
func TestBootFailureRestartsRecovery(t *testing.T) {
	c, clock, req, r, f := setup(t)
	warm(c, f, r)
	for i := 1; i <= MaxIdentities+1; i++ {
		c.ObserveVerdict(fmt.Sprintf("%064x", i), 503, "infrastructure_error", "")
	}
	c.ObserveAuthorized(f.Items[0])
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
	clock.add(15 * time.Second)
	c.ObserveAuthorized(f.Items[0])
	clock.add(10 * time.Second)
	c.ObserveVerdict(fmt.Sprintf("%064x", 1), 503, "infrastructure_error", "")
	b := c.bootBreaker
	if !c.bootClosed || b.successes != 0 || !b.first.IsZero() || !b.last.IsZero() || b.grant || b.failed != clock.Now() {
		t.Fatalf("tracked-key failure retained boot recovery evidence: %+v", b)
	}
	clock.add(5 * time.Second)
	c.ObserveAuthorized(f.Items[0])
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
	requireDecision(t, c, f, req, "health_unhealthy")
	clock.add(15 * time.Second)
	c.ObserveAuthorized(f.Items[0])
	clock.add(15 * time.Second)
	c.ObserveAuthorized(f.Items[0])
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
	requireDecision(t, c, f, req, "eligible")
}
func TestHealthyReceiptJournal24Hours(t *testing.T) {
	c, clock, req, r, f := setup(t)
	warm(c, f, r)
	id := f.Items[0]
	s := c.entries[id]
	s.evidenceDeadline = clock.Now().Add(25 * time.Hour)
	extendFixture(&f, clock.Now().Unix()+25*60*60)
	s.evidence.Local.Bindings["route"] = f.Context["route"]
	s.evidence.Local.Certificates[0].Route = f.Context["route"].(map[string]any)
	peak := 0
	for c.Mono() < 24*time.Hour {
		clock.add(11 * time.Second)
		c.ObserveAuthorized(id)
		c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
		peak = max(peak, len(s.receipts))
		if s.lastMiss != nil || len(s.receipts) > 256 {
			t.Fatalf("at %v: receipts=%d miss=%+v", c.Mono(), len(s.receipts), s.lastMiss)
		}
	}
	if s.retained != 0 {
		t.Fatal("soak consumed a permit")
	}
	requireDecision(t, c, f, req, "eligible")
	t.Logf("24h at 11s cadence: peak receipts=%d, elapsed=%v", peak, c.Mono())
}
func TestRetiredReceiptRejectsClockRollback(t *testing.T) {
	original, _, req, _, f := setup(t)
	start := time.Now()
	start = start.Add(time.Unix(2000, 0).Sub(start))
	clock := &fakeClock{now: start}
	c := New(Shadow, original.config, clock)
	c.ObserveAuthorized(f.Items[0])
	first := repairedGrant(t, c, f, 0, 0)
	results, _ := first(t.Context(), f.Items)
	fingerprint := sha256.Sum256([]byte(results[0].Grant))
	c.RefreshOnce(t.Context(), first)
	clock.add(11 * time.Second)
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
	clock.add(31 * time.Second)
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
	if _, exists := c.entries[f.Items[0]].receipts[fingerprint]; exists {
		t.Fatal("expired receipt not retired")
	}
	// Verification sees an otherwise-valid old JWS; monotonic time has passed
	// its original deadline and the watermark has passed its issuance second.
	clock.now = reviewWallShift(clock.now, -32)
	if c.Mono() != 42*time.Second || clock.Now().Unix() != 2010 {
		t.Fatal("invalid rollback clock")
	}
	c.RefreshOnce(t.Context(), first)
	requireDecision(t, c, f, req, "grant-replay")
	if _, exists := c.entries[f.Items[0]].receipts[fingerprint]; exists {
		t.Fatal("retired fingerprint re-admitted")
	}
	// Distinct valid signatures below and exactly at the watermark must also
	// fail closed: a bounded watermark cannot prove they were never received.
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 1, 1))
	requireDecision(t, c, f, req, "grant-replay")
	clock.add(time.Second)
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 1, 1))
	requireDecision(t, c, f, req, "grant-replay")
	clock.add(32 * time.Second)
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 1, 1))
	requireDecision(t, c, f, req, "eligible")
}
func TestEvictionPreservesNegativeHealth(t *testing.T) {
	for _, scope := range []string{"workspace", "key"} {
		t.Run(scope, func(t *testing.T) {
			c, clock, _, r, f := setup(t)
			warm(c, f, r)
			id := f.Items[0]
			status, reason := 402, "credit_exhausted"
			if scope == "key" {
				status, reason = 401, "key_invalid"
			}
			c.ObserveVerdict(id.LookupDigest, status, reason, "")
			clock.add(2 * time.Minute)
			c.mu.Lock()
			evicted := c.evictExpired()
			c.mu.Unlock()
			if !evicted || c.entries[id] != nil {
				t.Fatal("identity not evicted")
			}
			c.ObserveAuthorized(id)
			if scope == "workspace" && !c.workspaceClosed[id.WorkspaceID] || scope == "key" && !c.keyClosed[id.LookupDigest] {
				t.Fatal("eviction discarded negative health")
			}
		})
	}
}
func TestKeyFailureRestartsProbeWindow(t *testing.T) {
	c, clock, _, r, f := setup(t)
	warm(c, f, r)
	id := f.Items[0]
	c.ObserveVerdict(id.LookupDigest, 503, "infrastructure_error", "")
	c.ObserveAuthorized(id)
	clock.add(15 * time.Second)
	c.ObserveAuthorized(id)
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
	c.ObserveVerdict(id.LookupDigest, 503, "infrastructure_error", "")
	b := c.breakers[id.LookupDigest]
	if b.successes != 0 || !b.first.IsZero() || !b.last.IsZero() || b.grant {
		t.Fatalf("new failure retained recovery evidence: %+v", b)
	}
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 1, 0))
	clock.add(15 * time.Second)
	c.ObserveAuthorized(id)
	if !c.infrastructureClosed[id.LookupDigest] {
		t.Fatal("previous probes repaired new failure")
	}
	clock.add(15 * time.Second)
	c.ObserveAuthorized(id)
	clock.add(15 * time.Second)
	c.ObserveAuthorized(id)
	if c.infrastructureClosed[id.LookupDigest] {
		t.Fatal("new clean window failed to recover")
	}
}
func TestLowerGrantCannotRegressWorkspaceEpoch(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	id := f.Items[0]
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 2, 2))
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 1, 2))
	if c.entries[id].evidence.Health.Workspace.Epoch != 2 {
		t.Fatal("lower grant regressed workspace epoch")
	}
	x := c.Predecision(id.LookupDigest, req)
	defer x.Finish()
	if x.Decision().Eligible {
		t.Fatal("lower workspace epoch regained eligibility")
	}
}
