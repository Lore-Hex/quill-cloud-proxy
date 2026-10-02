package shadowcoord

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/speculation"
)

func repairedGrant(t testing.TB, c *Coordinator, f wireFixture, workspace, key int64) Refresh {
	t.Helper()
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	c.config.Keys[0].PublicKeyB64URL = base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	raw, _ := json.Marshal(f.Claims)
	claims := ParseRequest(raw)
	now := c.clock.Now().Unix()
	claims["workspace_epoch"] = workspace
	claims["key_epoch"] = key
	claims["iat"] = now
	claims["exp"] = now + 30
	claims["start_before"] = now + 28
	claims["history"].(map[string]any)["last_success_at"] = now
	claims["history"].(map[string]any)["window_start"] = now - 600
	claims["grant_id"] = fmt.Sprintf("repair-%d-%d-%d", now, workspace, key)
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": c.config.Keys[0].Kid, "typ": speculation.ShadowTyp})
	payload, _ := json.Marshal(claims)
	msg := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	grant := msg + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(msg)))
	if _, err := speculation.VerifyShadowRefreshGrant(grant, c.config.Keys, c.entries[f.Items[0]].evidence.Local.Bindings, now); err != nil {
		t.Fatal("test grant:", err)
	}
	return func(context.Context, []Identity) ([]Result, *Miss) {
		return []Result{{Identity: f.Items[0], Grant: grant}}, nil
	}
}
func requireDecision(t *testing.T, c *Coordinator, f wireFixture, req speculation.ParsedRequest, want string) {
	t.Helper()
	x := c.Predecision(f.Items[0].LookupDigest, req)
	defer x.Finish()
	if x.Decision().Reason != want {
		t.Fatalf("want %s: %+v", want, x.Decision())
	}
}
func TestEpochRecoveryScopes(t *testing.T) {
	for _, scope := range []string{"workspace", "key"} {
		t.Run(scope, func(t *testing.T) {
			c, clock, req, r, f := setup(t)
			warm(c, f, r)
			lookup := f.Items[0].LookupDigest
			status, reason, latch := 402, "billing_denied", "workspace_latched"
			if scope == "key" {
				status, reason, latch = 401, "key_invalid", "key_latched"
			}
			c.ObserveVerdict(lookup, status, reason, "")
			clock.add(16 * time.Minute)
			// Time, ordinary volume, expiry and same-epoch refresh never clear this latch.
			for range 50 {
				c.ObserveAuthorized(f.Items[0])
			}
			if scope == "workspace" && !c.workspaceClosed["w"] || scope == "key" && !c.keyClosed[lookup] {
				t.Fatal("time/volume cleared latch")
			}
			// Fresh independent policy remains mandatory, and is installed here as test evidence.
			c.entries[f.Items[0]].evidenceDeadline = clock.Now().Add(time.Hour)
			extendFixture(&f, clock.Now().Unix())
			c.entries[f.Items[0]].evidence.Local.Bindings["route"] = f.Context["route"]
			c.entries[f.Items[0]].evidence.Local.Certificates[0].Route = f.Context["route"].(map[string]any)
			c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
			requireDecision(t, c, f, req, latch)
			workspace, key := int64(1), int64(0)
			if scope == "key" {
				workspace, key = 0, 1
			}
			c.RefreshOnce(t.Context(), repairedGrant(t, c, f, workspace, key))
			requireDecision(t, c, f, req, "eligible")
			// A fresh denial records the new epoch; replaying that grant cannot repair it.
			c.ObserveVerdict(lookup, status, reason, "")
			c.RefreshOnce(t.Context(), repairedGrant(t, c, f, workspace, key))
			requireDecision(t, c, f, req, latch)
		})
	}
}
func TestInfrastructureRecovery(t *testing.T) {
	for _, boot := range []bool{false, true} {
		t.Run(fmt.Sprint(boot), func(t *testing.T) {
			c, clock, _, r, f := setup(t)
			warm(c, f, r)
			lookup := f.Items[0].LookupDigest
			failed := lookup
			if boot {
				failed = ""
			}
			old := c.ObservationVersion()
			c.ObserveVerdict(failed, 503, "infrastructure_error", "")
			closed := func() bool { return c.bootClosed || c.infrastructureClosed[lookup] }
			c.ObserveAuthorizedSince(f.Items[0], old)
			if c.breakers[lookup].successes != 0 || c.bootBreaker.successes != 0 {
				t.Fatal("old success repaired breaker")
			}
			other := Identity{WorkspaceID: "other", KeyID: "other", LookupDigest: strings.Repeat("b", 64)}
			if !boot {
				for range 3 {
					c.ObserveAuthorized(other)
				}
				if c.breakers[lookup].successes != 0 {
					t.Fatal("other key repaired breaker")
				}
			}
			c.ObserveAuthorized(f.Items[0])
			clock.add(15 * time.Second)
			c.ObserveAuthorized(f.Items[0])
			clock.add(14 * time.Second)
			c.ObserveAuthorized(f.Items[0])
			if !closed() {
				t.Fatal("recovered before 30s")
			}
			clock.add(time.Second)
			c.ObserveAuthorized(f.Items[0])
			if !closed() {
				t.Fatal("recovered without fresh grant")
			}
			// Signed grant horizons and history are moved by the fixture signer below.
			extendFixture(&f, clock.Now().Unix())
			c.entries[f.Items[0]].evidence.Local.Bindings["route"] = f.Context["route"]
			c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
			if closed() {
				t.Fatal("clean probes + fresh grant failed to recover", c.entries[f.Items[0]].lastMiss)
			}
		})
	}
}
func extendFixture(f *wireFixture, now int64) {
	f.Claims["key_expires_at"] = now + 100
	f.Claims["trust_fresh_until"] = now + 100
	f.Claims["route"].(map[string]any)["price_expires_at"] = now + 100
	f.Context["route"].(map[string]any)["price_expires_at"] = now + 100
}
func TestProductionRecoverySequence(t *testing.T) {
	c, clock, req, r, f := setup(t)
	warm(c, f, r)
	c.ObserveVerdict(strings.Repeat("b", 64), 401, "key_invalid", "")
	if c.reconfirm != 0 || c.bootClosed {
		t.Fatal("unknown invalid credential altered health")
	}
	c.ObserveVerdict(strings.Repeat("c", 64), 402, "credit_exhausted", "")
	requireDecision(t, c, f, req, "coverage-unconfirmed")
	c.RefreshOnce(t.Context(), r)
	lookup := f.Items[0].LookupDigest
	c.ObserveVerdict(lookup, 503, "infrastructure_error", "")
	c.ObserveAuthorized(f.Items[0]) // ordinary successful retry is only one probe
	requireDecision(t, c, f, req, "health_unhealthy")
	clock.add(15 * time.Second)
	c.ObserveAuthorized(f.Items[0])
	clock.add(15 * time.Second)
	c.ObserveAuthorized(f.Items[0])
	extendFixture(&f, clock.Now().Unix())
	c.entries[f.Items[0]].evidence.Local.Bindings["route"] = f.Context["route"]
	c.entries[f.Items[0]].evidence.Local.Certificates[0].Route = f.Context["route"].(map[string]any)
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
	requireDecision(t, c, f, req, "eligible")
}
func TestUnresolvedDenialRequiresLaterSend(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	c.RefreshOnce(t.Context(), func(ctx context.Context, ids []Identity) ([]Result, *Miss) {
		c.ObserveVerdict(strings.Repeat("b", 64), 402, "credit_exhausted", "")
		return r(ctx, ids)
	})
	requireDecision(t, c, f, req, "coverage-unconfirmed")
	if c.bootClosed || c.reconfirm == 0 {
		t.Fatal("wrong conservative invalidation")
	}
	c.RefreshOnce(t.Context(), r)
	requireDecision(t, c, f, req, "eligible")
}
func TestConflictAndRequestOnlyVerdicts(t *testing.T) {
	for _, resolved := range []Identity{{WorkspaceID: "other"}, {WorkspaceID: "w", KeyID: "other"}, {WorkspaceID: "w", LookupDigest: strings.Repeat("b", 64)}} {
		c, _, req, r, f := setup(t)
		warm(c, f, r)
		c.ObserveResolvedVerdict(f.Items[0].LookupDigest, 401, "key_invalid", "", resolved)
		requireDecision(t, c, f, req, "coverage-unconfirmed")
	}
	for _, status := range []int{400, 401, 403, 404, 422} {
		c, _, req, r, f := setup(t)
		warm(c, f, r)
		c.ObserveVerdict(strings.Repeat("b", 64), status, "request_invalid", "")
		requireDecision(t, c, f, req, "eligible")
	}
}
func TestIdentityCapacityEvictionAndRecord(t *testing.T) {
	c, clock, _, r, f := setup(t)
	warm(c, f, r)
	for i := 1; i < MaxIdentities; i++ {
		c.ObserveAuthorized(Identity{WorkspaceID: fmt.Sprint(i), KeyID: "k", LookupDigest: fmt.Sprintf("%064x", i)})
	}
	// No-expiry learned identities can be evicted, but retained liability cannot.
	for _, s := range c.entries {
		s.evidenceDeadline = clock.Now().Add(time.Minute)
	}
	next := Identity{WorkspaceID: "new", KeyID: "k", LookupDigest: strings.Repeat("f", 64)}
	c.ObserveAuthorized(next)
	if c.entries[next] != nil {
		t.Fatal("capacity exceeded")
	}
	found := false
	for len(c.records) > 0 {
		if record := <-c.records; record.Kind == "capacity" && record.Miss.Code == "identity-capacity" {
			found = true
		}
	}
	if !found {
		t.Fatal("silent capacity truncation")
	}
	clock.add(2 * time.Minute)
	c.entries[f.Items[0]].retained = 1
	c.ObserveAuthorized(next)
	if c.entries[next] == nil || c.entries[f.Items[0]] == nil || len(c.entries) != MaxIdentities {
		t.Fatal("expired identity not evicted or liability evicted")
	}
	if len(c.byLookup) != MaxIdentities || len(c.order) != MaxIdentities {
		t.Fatal("eviction indices stale")
	}
}
func TestInputDepthBound(t *testing.T) {
	raw := []byte(`{"unknown":` + strings.Repeat("[", MaxInputDepth) + "0" + strings.Repeat("]", MaxInputDepth) + "}")
	if testing.AllocsPerRun(100, func() {
		if ParseRequest(raw) != nil {
			t.Fatal("deep request decoded")
		}
	}) != 0 {
		t.Fatal("depth checked after decode")
	}
	for _, raw := range []string{`{"x":"[[[{\\\""}`, `{"x":[{"y":1}]}`} {
		if ParseRequest([]byte(raw)) == nil {
			t.Fatal("shallow string/containers rejected", raw)
		}
	}
}
func BenchmarkShadowCostSplit(b *testing.B) {
	c, _, _, r, f := setup(b)
	warm(c, f, r)
	raw := []byte(`{"model":"fixture-text","stream":true,"messages":[{"role":"user","content":"` + strings.Repeat("x", 7900) + `"}],"max_tokens":512,"provider":{"usage":"Credits"}}`)
	req := speculation.ParsedRequest{Body: ParseRequest(raw), RouteType: "chat.completions"}
	s := c.entries[f.Items[0]]
	b.Run("second-decode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			ParseRequest(raw)
		}
	})
	b.Run("payload-preparation", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			speculation.PreparePayload(s.cached.verified, s.evidence.Local.Certificates, req)
		}
	})
	b.Run("eligibility", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			speculation.EvaluateEligibility(s.cached.received, s.evidence.Local, req, s.evidence.Health, 0)
		}
	})
}

func TestRecoveryRequiresFreshEvidenceAndSpanningSuccesses(t *testing.T) {
	c, clock, _, r, f := setup(t)
	warm(c, f, r)
	id := f.Items[0]
	c.ObserveVerdict(id.LookupDigest, 503, "infrastructure_error", "")
	for range 3 {
		c.ObserveAuthorized(id)
	}
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
	clock.add(30 * time.Second)
	// A late grant cannot turn three simultaneous successes into a 30s span.
	c.mu.Lock()
	c.reopenInfrastructure(id.LookupDigest, clock.Now())
	c.mu.Unlock()
	if !c.infrastructureClosed[id.LookupDigest] {
		t.Fatal("success span fabricated by time alone")
	}
	c.ObserveAuthorized(id)
	if c.infrastructureClosed[id.LookupDigest] {
		t.Fatal("qualifying success failed to reopen")
	}
	// A new failure resets both successes and the post-failure grant requirement.
	c.ObserveVerdict(id.LookupDigest, 503, "infrastructure_error", "")
	c.ObserveAuthorized(id)
	clock.add(15 * time.Second)
	c.ObserveAuthorized(id)
	clock.add(15 * time.Second)
	c.ObserveAuthorized(id)
	if !c.infrastructureClosed[id.LookupDigest] {
		t.Fatal("pre-failure grant repaired new failure")
	}
}
func TestHigherEpochCannotRepairOtherScope(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	id := f.Items[0]
	c.ObserveVerdict(id.LookupDigest, 402, "credit_exhausted", "")
	c.ObserveVerdict(id.LookupDigest, 401, "key_invalid", "")
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 1))
	requireDecision(t, c, f, req, "workspace_latched")
	if !c.workspaceClosed[id.WorkspaceID] || c.keyClosed[id.LookupDigest] {
		t.Fatal("wrong repaired scope")
	}
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 1, 1))
	requireDecision(t, c, f, req, "eligible")
}
func TestCapacityFallbackReconfirmation(t *testing.T) {
	c, _, req, r, f := setup(t)
	warm(c, f, r)
	for i := range MaxIdentities {
		c.ObserveResolvedVerdict(fmt.Sprintf("%064x", i+1), 402, "credit_exhausted", "", Identity{WorkspaceID: fmt.Sprint("other", i)})
	}
	c.ObserveResolvedVerdict(strings.Repeat("f", 64), 402, "credit_exhausted", "", Identity{WorkspaceID: "overflow"})
	if c.bootClosed {
		t.Fatal("capacity permanently closed boot")
	}
	requireDecision(t, c, f, req, "coverage-unconfirmed")
	c.RefreshOnce(t.Context(), r)
	requireDecision(t, c, f, req, "eligible")
}
func TestInfrastructureCapacityBootRecovery(t *testing.T) {
	c, clock, _, r, f := setup(t)
	warm(c, f, r)
	for i := range MaxIdentities + 1 {
		c.ObserveVerdict(fmt.Sprintf("%064x", i+1), 503, "infrastructure_error", "")
	}
	if !c.bootClosed || len(c.infrastructureClosed) != MaxIdentities {
		t.Fatal("infrastructure capacity")
	}
	c.ObserveAuthorized(f.Items[0])
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
	clock.add(15 * time.Second)
	c.ObserveAuthorized(f.Items[0])
	clock.add(15 * time.Second)
	c.ObserveAuthorized(f.Items[0])
	if c.bootClosed {
		t.Fatal("boot fallback never recovers")
	}
}
func TestGrantReceiptCannotRepairLaterLatch(t *testing.T) {
	c, _, _, r, f := setup(t)
	warm(c, f, r)
	id := f.Items[0]
	before := c.ObservationVersion()
	c.ObserveVerdict(id.LookupDigest, 402, "credit_exhausted", "")
	c.ObserveVerdict(id.LookupDigest, 503, "infrastructure_error", "")
	c.mu.Lock()
	c.recoverGrant(id, c.entries[id], map[string]any{"workspace_epoch": int64(1), "key_epoch": int64(0)}, before, before)
	c.mu.Unlock()
	if !c.workspaceClosed[id.WorkspaceID] || c.breakers[id.LookupDigest].grant {
		t.Fatal("pre-denial receipt repaired newer failure")
	}
}

func TestBootRecoveryCountsUncachedOrdinarySuccess(t *testing.T) {
	c, clock, _, r, f := setup(t)
	warm(c, f, r)
	for i := 1; i < MaxIdentities; i++ {
		c.ObserveAuthorized(Identity{WorkspaceID: fmt.Sprint(i), KeyID: "k", LookupDigest: fmt.Sprintf("%064x", i)})
	}
	for _, s := range c.entries {
		s.evidenceDeadline = clock.Now().Add(time.Hour)
	}
	c.ObserveVerdict("", 503, "infrastructure_error", "")
	c.RefreshOnce(t.Context(), repairedGrant(t, c, f, 0, 0))
	uncached := Identity{WorkspaceID: "uncached", KeyID: "k", LookupDigest: strings.Repeat("f", 64)}
	c.ObserveAuthorized(uncached)
	clock.add(15 * time.Second)
	c.ObserveAuthorized(uncached)
	clock.add(15 * time.Second)
	c.ObserveAuthorized(uncached)
	if c.entries[uncached] != nil || c.bootClosed {
		t.Fatal("identity capacity swallowed clean boot probes")
	}
}
