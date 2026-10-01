package speculation

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

type eligibilityCase struct {
	grant  ReceivedGrant
	local  LocalContext
	req    ParsedRequest
	health LocalHealth
}

func eligibleCase(t testing.TB) eligibilityCase {
	t.Helper()
	h := newHarness(t)
	g, r := ReceiveGrant(h.real, time.Unix(1700000000, 0), 0, 0)
	if r != ReasonEligible {
		t.Fatal(r)
	}
	context := m(h.bundle["context"])
	route := m(context["route"])
	req := ParsedRequest{Body: map[string]any{"model": "fixture-text", "messages": []any{map[string]any{"role": "user", "content": "fixture"}}, "stream": true, "max_tokens": int64(512), "provider": map[string]any{"usage": "Credits"}}, RouteType: "chat.completions"}
	req.CallerIdempotency = CaptureCallerIdempotency(false, req.Body)
	cert := AdapterCertificate{Route: route, BoundAlgorithm: ConservativeUTF8Bytes, FramingKnown: true, FramingTokens: 32, HardOutputCap: true, SingleAttempt: true, NoHiddenTools: true, NoHiddenReasoning: true, VendorPricesBounded: true}
	return eligibilityCase{g, LocalContext{Bindings: context, Certificates: []AdapterCertificate{cert}, RequestPolicyHash: s(route["routing_policy_hash"]), OwnerBootID: "boot-a", OwnerBootCount: 1, PilotAllowed: true, PaidProvenance: true, KeyEligible: true, BootVerified: true, PolicyFresh: true, StageDEnabled: true}, req, LocalHealth{WorkspaceID: "w1", KeyID: "k1", Provider: "fixture-provider", Workspace: ScopeHealth{Known: true, Healthy: true, Epoch: 3}, Key: ScopeHealth{Known: true, Healthy: true, Epoch: 5}, ProviderKnown: true, ProviderHealthy: true, InfrastructureHealthy: true}}
}
func (c eligibilityCase) evaluate() EligibilitySnapshot {
	return EvaluateEligibility(c.grant, c.local, c.req, c.health, 0)
}
func expectReason(t testing.TB, c eligibilityCase, want Reason) {
	t.Helper()
	got := c.evaluate()
	if got.Dispatch.Reason != want || got.Dispatch.Eligible != (want == ReasonEligible) || got.Shadow.Reason != want || got.ShadowDispatchAllowed {
		t.Fatalf("want %s, got %+v", want, got)
	}
}
func TestEligibilityExclusions(t *testing.T) {
	cases := []struct {
		name   string
		reason Reason
		edit   func(*eligibilityCase)
	}{
		{"stream", ReasonChat, func(c *eligibilityCase) { c.req.Body["stream"] = false }},
		{"responses", ReasonChat, func(c *eligibilityCase) { c.req.RouteType = "responses" }},
		{"credits", ReasonCredits, func(c *eligibilityCase) { delete(c.req.Body, "provider") }},
		{"tier", ReasonTier, func(c *eligibilityCase) { c.req.Body["service_tier"] = "Default" }},
		{"header_idempotency", ReasonIdempotency, func(c *eligibilityCase) { c.req.CallerIdempotency = CaptureCallerIdempotency(true, c.req.Body) }},
		{"body_idempotency", ReasonIdempotency, func(c *eligibilityCase) {
			c.req.Body["idempotency_key"] = ""
			c.req.CallerIdempotency = CaptureCallerIdempotency(false, c.req.Body)
			delete(c.req.Body, "idempotency_key")
		}},
		{"late_body_idempotency", ReasonIdempotency, func(c *eligibilityCase) { c.req.Body["idempotency_key"] = "x" }},
		{"provenance", ReasonProvenance, func(c *eligibilityCase) { c.req.CallerIdempotency = CallerIdempotency{} }},
		{"receipts", ReasonReceipts, func(c *eligibilityCase) { c.req.InferenceReceipts = true }},
		{"tools", ReasonTools, func(c *eligibilityCase) { c.req.Body["tools"] = []any{} }},
		{"reasoning", ReasonReasoning, func(c *eligibilityCase) { c.req.Body["reasoning_effort"] = "none" }},
		{"media", ReasonMedia, func(c *eligibilityCase) { c.req.Body["modalities"] = []any{"text", "audio"} }},
		{"byok", ReasonBYOK, func(c *eligibilityCase) { c.req.BYOK = true }},
		{"custom_model", ReasonCustomModel, func(c *eligibilityCase) { c.req.CustomModel = true }},
		{"orchestration", ReasonOrchestration, func(c *eligibilityCase) { c.req.Orchestration = true }},
		{"fusion", ReasonOrchestration, func(c *eligibilityCase) { c.req.Body["fusion"] = true }},
		{"fan_out", ReasonOrchestration, func(c *eligibilityCase) { c.req.Body["models"] = []any{"a", "b"} }},
		{"confidential", ReasonConfidential, func(c *eligibilityCase) { c.req.ConfidentialOnly = true }},
		{"extra_cost", ReasonExtraCost, func(c *eligibilityCase) { c.req.ExtraReservationCost = 1 }},
		{"response_model", ReasonResponseModel, func(c *eligibilityCase) { c.req.ResponseModel = "alias" }},
		{"rich_preferences", ReasonPreferences, func(c *eligibilityCase) { m(c.req.Body["provider"])["sort"] = "price" }},
		{"external_prompt", ReasonExternalPrompt, func(c *eligibilityCase) { c.req.Body["prompt_url"] = "https://invalid" }},
		{"cache_write", ReasonCacheWrite, func(c *eligibilityCase) { c.req.Body["prompt_cache_options"] = map[string]any{} }},
		{"attribution", ReasonAttribution, func(c *eligibilityCase) { c.req.Body["user"] = "u" }},
		{"route_count", ReasonRoute, func(c *eligibilityCase) { c.local.Certificates = append(c.local.Certificates, c.local.Certificates[0]) }},
		{"route_missing", ReasonRoute, func(c *eligibilityCase) { c.local.Certificates = nil }},
		{"route_model", ReasonRoute, func(c *eligibilityCase) { c.req.Body["model"] = "different" }},
		{"route_binding", ReasonBinding, func(c *eligibilityCase) { c.local.Bindings["route"] = nil }},
		{"binding", ReasonBinding, func(c *eligibilityCase) { c.local.Bindings["generation"] = int64(8) }},
		{"owners", ReasonOwner, func(c *eligibilityCase) { c.local.OwnerBootCount = 2 }},
		{"owner_boot", ReasonOwner, func(c *eligibilityCase) { c.local.OwnerBootID = "other" }},
		{"pilot", ReasonTrust, func(c *eligibilityCase) { c.local.PilotAllowed = false }},
		{"paid", ReasonTrust, func(c *eligibilityCase) { c.local.PaidProvenance = false }},
		{"key", ReasonTrust, func(c *eligibilityCase) { c.local.KeyEligible = false }},
		{"boot", ReasonTrust, func(c *eligibilityCase) { c.local.BootVerified = false }},
		{"policy", ReasonPolicy, func(c *eligibilityCase) { c.local.PolicyFresh = false }},
		{"request_policy", ReasonPolicy, func(c *eligibilityCase) { c.local.RequestPolicyHash = "different" }},
		{"stage_d", ReasonStageD, func(c *eligibilityCase) { c.local.StageDEnabled = false }},
		{"grant", ReasonGrant, func(c *eligibilityCase) { c.grant = ReceivedGrant{} }},
		{"deadline", ReasonDeadline, func(c *eligibilityCase) { c.grant.deadline = 0 }},
	}
	expectReason(t, eligibleCase(t), ReasonEligible)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { c := eligibleCase(t); tc.edit(&c); expectReason(t, c, tc.reason) })
	}
}

func TestMissingHealthAndScopedEpochs(t *testing.T) {
	cases := []struct {
		name   string
		reason Reason
		edit   func(*LocalHealth)
	}{
		{"missing", ReasonHealthMissing, func(h *LocalHealth) { *h = LocalHealth{} }},
		{"workspace_missing", ReasonHealthMissing, func(h *LocalHealth) { h.Workspace.Known = false }},
		{"key_missing", ReasonHealthMissing, func(h *LocalHealth) { h.Key.Known = false }},
		{"provider_missing", ReasonHealthMissing, func(h *LocalHealth) { h.ProviderKnown = false }},
		{"wrong_workspace", ReasonHealthMissing, func(h *LocalHealth) { h.WorkspaceID = "other" }},
		{"wrong_key", ReasonHealthMissing, func(h *LocalHealth) { h.KeyID = "other" }},
		{"wrong_provider", ReasonHealthMissing, func(h *LocalHealth) { h.Provider = "other" }},
		{"workspace_latch", ReasonWorkspaceLatch, func(h *LocalHealth) { h.Workspace.Latched = true }},
		{"key_latch", ReasonKeyLatch, func(h *LocalHealth) { h.Key.Latched = true }},
		{"workspace_unhealthy", ReasonHealth, func(h *LocalHealth) { h.Workspace.Healthy = false }},
		{"key_unhealthy", ReasonHealth, func(h *LocalHealth) { h.Key.Healthy = false }},
		{"provider_breaker", ReasonHealth, func(h *LocalHealth) { h.ProviderHealthy = false }},
		{"infrastructure_breaker", ReasonHealth, func(h *LocalHealth) { h.InfrastructureHealthy = false }},
		{"workspace_epoch", ReasonWorkspaceEpoch, func(h *LocalHealth) { h.Workspace.Epoch++ }},
		{"key_epoch", ReasonKeyEpoch, func(h *LocalHealth) { h.Key.Epoch++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { c := eligibleCase(t); tc.edit(&c.health); expectReason(t, c, tc.reason) })
	}
	// Reuse the frozen verdict taxonomy rather than inferring scope from status.
	v, err := ClassifyVerdict(VerdictInput{Source: "authenticated_router", Status: 403, Reason: "key_revoked", WorkspaceID: "w1", KeyID: "other"})
	if err != nil || v.DurableScope != "key" {
		t.Fatal(v, err)
	}
	expectReason(t, eligibleCase(t), ReasonEligible) // a different key's latch is not this key's health
}

// Re-sign independent test claims; no fixture bytes are changed.
func signedEligibilityToken(t testing.TB, h harness, claims map[string]any, typ string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "issuer-fixture", "typ": typ})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(128 + i)
	}
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(message)))
}
func TestDispatchAuthoritySeparation(t *testing.T) {
	h := newHarness(t)
	c := eligibleCase(t)
	shadow, r := ReceiveGrant(h.shadow, time.Unix(1700000000, 0), 0, 0)
	if r != ReasonEligible {
		t.Fatal(r)
	}
	c.grant = shadow
	got := c.evaluate()
	if got.Dispatch.Eligible || got.Dispatch.Reason != ReasonShadow || !got.Shadow.Eligible || got.ShadowDispatchAllowed {
		t.Fatal(got)
	}
	for _, typ := range []string{"spend-lease+jws", "spend-lease-shadow+jws", ShadowTyp} {
		t.Run(typ, func(t *testing.T) {
			claims, _ := h.real.Claims()
			token := signedEligibilityToken(t, h, claims, typ)
			g, err := VerifyGrant(token, h.keys, m(h.bundle["context"]), 1700000000, false)
			if err != ProtocolError("type") || g.Compact() != "" {
				t.Fatal("foreign authority", g, err)
			}
		})
	}
	c.req.ConfidentialOnly = true
	expectReason(t, c, ReasonConfidential)
}
func TestHistoryDistinctThreshold(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		name       string
		count, seq int64
		want       error
	}{{"twenty", 20, 20, nil}, {"nineteen", 19, 19, ProtocolError("history_count")}, {"retry_counted_twice", 20, 19, ProtocolError("history_count")}} {
		t.Run(tc.name, func(t *testing.T) {
			claims, _ := h.real.Claims()
			hist := m(claims["history"])
			hist["count"], hist["sequence"] = tc.count, tc.seq
			_, err := VerifyGrant(signedEligibilityToken(t, h, claims, RealTyp), h.keys, m(h.bundle["context"]), 1700000000, false)
			if err != tc.want {
				t.Fatalf("want %v got %v", tc.want, err)
			}
		})
	}
}
func TestConcurrentRenewalStaleDelivery(t *testing.T) {
	h := newHarness(t)
	c := eligibleCase(t)
	claims, _ := h.real.Claims()
	claims["generation"] = int64(8)
	claims["grant_id"] = "g2"
	claims["workspace_epoch"] = int64(4)
	context := m(loadFixture(t, "grant-permit-tokens.json")["context"])
	context["generation"], context["workspace_epoch"] = int64(8), int64(4)
	newer, err := VerifyGrant(signedEligibilityToken(t, h, claims, RealTyp), h.keys, context, 1700000000, false)
	if err != nil {
		t.Fatal(err)
	}
	fresh, r := ReceiveGrant(newer, time.Unix(1700000005, 0), Monotonic(5*time.Second), 0)
	if r != ReasonEligible {
		t.Fatal(r)
	}
	c.local.Bindings = context
	c.health.Workspace.Epoch = 4
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, e := RenewalVerdict(h.real, newer); v != "renewed" || e != nil {
				t.Errorf("renewal %s %v", v, e)
			}
			if _, e := RenewalVerdict(newer, h.real); e == nil {
				t.Error("stale renewal accepted")
			}
			old := EvaluateEligibility(c.grant, c.local, c.req, c.health, Monotonic(5*time.Second))
			if old.Dispatch.Reason != ReasonWorkspaceEpoch {
				t.Error(old)
			}
			good := EvaluateEligibility(fresh, c.local, c.req, c.health, Monotonic(5*time.Second))
			if !good.Dispatch.Eligible {
				t.Error(good)
			}
			latched := c.health
			latched.Key.Latched = true
			if got := EvaluateEligibility(fresh, c.local, c.req, latched, Monotonic(5*time.Second)); got.Dispatch.Reason != ReasonKeyLatch {
				t.Error(got)
			}
		}()
	}
	wg.Wait()
	// Neither receipt nor stale delivery has modified either immutable grant.
	if fresh.deadline != Monotonic(28*time.Second) || c.grant.deadline != fresh.deadline {
		t.Fatal("renewal added time")
	}
}

func TestEveryPublicExclusionField(t *testing.T) {
	groups := map[Reason]string{ReasonReceipts: "inference_receipt inference_receipts", ReasonTools: "tools tool_choice functions function_call plugins max_tool_calls web_search_options parallel_tool_calls", ReasonReasoning: "reasoning reasoning_effort thinking", ReasonMedia: "audio modalities image video", ReasonOrchestration: "models fusion decide advisor subagent batch depth", ReasonExternalPrompt: "prompt_url external_prompt", ReasonCacheWrite: "prompt_cache_key prompt_cache_options", ReasonAttribution: "user session_id trace metadata tags app http_referer app_categories request_fingerprint"}
	for reason, fields := range groups {
		for _, field := range strings.Fields(fields) {
			t.Run(field, func(t *testing.T) { c := eligibleCase(t); c.req.Body[field] = nil; expectReason(t, c, reason) })
		}
	}
	for _, field := range strings.Fields("usage_type billing max_price jurisdiction sort options quantizations preferred_max_latency preferred_min_throughput min_privacy country headquarters_country provider_country zdr") {
		t.Run(field, func(t *testing.T) {
			c := eligibleCase(t)
			m(c.req.Body["provider"])[field] = nil
			expectReason(t, c, ReasonPreferences)
		})
	}
}
