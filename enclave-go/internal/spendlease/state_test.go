package spendlease

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
)

func stateTestToken(t *testing.T, issuer testIssuer, now time.Time, generation, cap int64, leaseID string) string {
	t.Helper()
	claims := validTestClaims(now)
	claims.Generation = generation
	claims.CapMicro = cap
	claims.LeaseID = leaseID
	claims.Catalog.Candidates[0].RequestPriceMicro = 3
	return signTestLease(t, issuer, claims, JWSType, issuer.kid, JWK{
		KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(issuer.public),
	})
}

func TestStageCAdmissionCASDedupAndMonotonicLedgerRemaining(t *testing.T) {
	now := time.Unix(2_000_000_000, 123_000_000)
	issuer, verifier := newTestIssuer(t, now)
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	signer, err := receipt.NewSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest := sha256.Sum256([]byte("policy"))
	policyHash := hex.EncodeToString(policyDigest[:])
	claims := validTestClaims(now)
	claims.Authoritative = true
	claims.LocalAdmissionAllowed = true
	claims.RoutingPolicyHash = policyHash
	claims.BootKID = signer.Kid()
	claims.CapMicro = 12
	claims.Catalog.Candidates[0].RequestPriceMicro = 3
	claims.Catalog.Candidates[0].UpstreamModel = "upstream-1"
	claims.Catalog.Candidates[0].UsageType = "Credits"
	token := signTestLease(t, issuer, claims, JWSType, issuer.kid, JWK{
		KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(issuer.public),
	})
	state := NewShadowState(verifier, signer.Kid())
	state.SetLocalAdmission(true)
	state.SetRegistered(true)
	if err := state.HandleResponse(claims.KeyHash, claims.WorkspaceID, &Response{Token: &token, LeaseStatus: "active"}, now); err != nil {
		t.Fatal(err)
	}
	request := EstimateRequest{Model: claims.Catalog.Candidates[0].Model, RouteType: claims.Catalog.Candidates[0].RouteType, Region: claims.Catalog.Candidates[0].Region, EstimatedInputTokens: 1}
	first, err := state.TryAdmit(claims.KeyHash, "idem", policyHash, request, now, signer)
	if err != nil || first == nil {
		t.Fatalf("first admission = %#v, err=%v", first, err)
	}
	if first.RemainingAfterMicro != 9 || first.EstimateMicro != 3 {
		t.Fatalf("first admission = %#v", first)
	}
	if duplicate, err := state.TryAdmit(claims.KeyHash, "idem", policyHash, request, now, signer); err != nil || duplicate != nil {
		t.Fatalf("in-flight duplicate = %#v, err=%v", duplicate, err)
	}
	ledger := int64(7)
	state.ObserveReserve(claims.KeyHash, claims.LeaseID, claims.Generation, &ledger, "", true)
	staleHigher := int64(10)
	state.ObserveReserve(claims.KeyHash, claims.LeaseID, claims.Generation, &staleHigher, "", true)
	first.Release()
	second, err := state.TryAdmit(claims.KeyHash, "idem-2", policyHash, request, now, signer)
	if err != nil || second == nil || second.RemainingAfterMicro != 4 {
		t.Fatalf("second admission = %#v, err=%v", second, err)
	}
	second.Release()
	cutoff := time.Unix(claims.ExpiresAt, 0).Add(-AdmissionMargin)
	if late, lateErr := state.TryAdmit(claims.KeyHash, "inside-margin", policyHash, request, cutoff, signer); lateErr != nil || late != nil {
		t.Fatalf("admission at reserve margin = %#v, err=%v", late, lateErr)
	}
}

func TestStageCTryAdmitEnforcesRemainingBudget(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	issuer, verifier := newTestIssuer(t, now)
	signer, err := receipt.NewSignerFromSeed(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	policyHash := strings.Repeat("a", sha256.Size*2)
	claims := validTestClaims(now)
	claims.Authoritative = true
	claims.LocalAdmissionAllowed = true
	claims.RoutingPolicyHash = policyHash
	claims.BootKID = signer.Kid()
	claims.CapMicro = 100
	claims.Catalog.Candidates[0].RequestPriceMicro = 0
	claims.Catalog.Candidates[0].InputPriceMicroPerMTok = microPerMillion
	claims.Catalog.Candidates[0].UpstreamModel = "upstream-1"
	claims.Catalog.Candidates[0].UsageType = "Credits"
	token := signTestLease(t, issuer, claims, JWSType, issuer.kid, JWK{
		KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(issuer.public),
	})

	newState := func(t *testing.T) *ShadowState {
		t.Helper()
		state := NewShadowState(verifier, signer.Kid())
		state.SetLocalAdmission(true)
		state.SetRegistered(true)
		if err := state.HandleResponse(claims.KeyHash, claims.WorkspaceID, &Response{Token: &token, LeaseStatus: "active"}, now); err != nil {
			t.Fatal(err)
		}
		return state
	}
	request := func(estimatedInputTokens int64) EstimateRequest {
		return EstimateRequest{
			Model: claims.Catalog.Candidates[0].Model, RouteType: claims.Catalog.Candidates[0].RouteType,
			Region: claims.Catalog.Candidates[0].Region, EstimatedInputTokens: estimatedInputTokens,
		}
	}

	t.Run("refuses estimate above remaining and releases scope", func(t *testing.T) {
		state := newState(t)
		admission, err := state.TryAdmit(claims.KeyHash, "same-scope", policyHash, request(150), now, signer)
		if err != nil || admission != nil {
			t.Fatalf("oversized admission = %#v, err=%v; want nil, nil", admission, err)
		}
		current := state.lookup(claims.KeyHash, false).current.Load()
		if remaining := current.remaining.Load(); remaining != 100 {
			t.Fatalf("remaining after refusal = %d, want 100", remaining)
		}
		if status := current.status.Load(); status != grantActive {
			t.Fatalf("status after refusal = %s, want active", stateName(status))
		}

		admission, err = state.TryAdmit(claims.KeyHash, "same-scope", policyHash, request(50), now, signer)
		if err != nil || admission == nil {
			t.Fatalf("smaller admission after refusal = %#v, err=%v; want admission", admission, err)
		}
		defer admission.Release()
		if remaining := current.remaining.Load(); remaining != 50 {
			t.Fatalf("remaining after smaller admission = %d, want 50", remaining)
		}
	})

	t.Run("admits estimate equal to remaining and exhausts grant", func(t *testing.T) {
		state := newState(t)
		admission, err := state.TryAdmit(claims.KeyHash, "exact-cap", policyHash, request(100), now, signer)
		if err != nil || admission == nil {
			t.Fatalf("exact-cap admission = %#v, err=%v; want admission", admission, err)
		}
		defer admission.Release()
		current := state.lookup(claims.KeyHash, false).current.Load()
		if remaining := current.remaining.Load(); remaining != 0 {
			t.Fatalf("remaining after exact-cap admission = %d, want 0", remaining)
		}
		if status := current.status.Load(); status != grantExhausted {
			t.Fatalf("status after exact-cap admission = %s, want exhausted", stateName(status))
		}
	})
}

func TestStageCConcurrentAdmissionCASNeverExceedsGrantCap(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	issuer, verifier := newTestIssuer(t, now)
	signer, err := receipt.NewSignerFromSeed(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	policyHash := strings.Repeat("a", sha256.Size*2)
	claims := validTestClaims(now)
	claims.Authoritative = true
	claims.LocalAdmissionAllowed = true
	claims.RoutingPolicyHash = policyHash
	claims.BootKID = signer.Kid()
	claims.CapMicro = 12
	claims.Catalog.Candidates[0].RequestPriceMicro = 3
	claims.Catalog.Candidates[0].UpstreamModel = "upstream-1"
	claims.Catalog.Candidates[0].UsageType = "Credits"
	token := signTestLease(t, issuer, claims, JWSType, issuer.kid, JWK{
		KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(issuer.public),
	})
	state := NewShadowState(verifier, signer.Kid())
	state.SetLocalAdmission(true)
	state.SetRegistered(true)
	if err := state.HandleResponse(claims.KeyHash, claims.WorkspaceID, &Response{Token: &token, LeaseStatus: "active"}, now); err != nil {
		t.Fatal(err)
	}
	request := EstimateRequest{
		Model: claims.Catalog.Candidates[0].Model, RouteType: claims.Catalog.Candidates[0].RouteType,
		Region: claims.Catalog.Candidates[0].Region, EstimatedInputTokens: 1,
	}
	admissions := make(chan *Admission, 32)
	errorsSeen := make(chan error, 32)
	var group sync.WaitGroup
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			admission, admitErr := state.TryAdmit(claims.KeyHash, fmt.Sprintf("idem-%d", index), policyHash, request, now, signer)
			if admitErr != nil {
				errorsSeen <- admitErr
			}
			if admission != nil {
				admissions <- admission
			}
		}(index)
	}
	group.Wait()
	close(admissions)
	close(errorsSeen)
	for admitErr := range errorsSeen {
		t.Errorf("concurrent admission: %v", admitErr)
	}
	count := 0
	for admission := range admissions {
		count++
		admission.Release()
	}
	if count != 4 {
		t.Fatalf("admissions = %d, want exactly cap/estimate = 4", count)
	}
	current := state.lookup(claims.KeyHash, false).current.Load()
	if remaining := current.remaining.Load(); remaining != 0 {
		t.Fatalf("remaining = %d, want 0", remaining)
	}
}

func TestStageCAuthoritativeVerificationAndAdmissionAreFlagGated(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	issuer, verifier := newTestIssuer(t, now)
	claims := validTestClaims(now)
	claims.Authoritative = true
	claims.LocalAdmissionAllowed = true
	claims.RoutingPolicyHash = strings.Repeat("a", sha256.Size*2)
	claims.Catalog.Candidates[0].UpstreamModel = "upstream"
	claims.Catalog.Candidates[0].UsageType = "Credits"
	token := signTestLease(t, issuer, claims, JWSType, issuer.kid, JWK{})
	state := NewShadowState(verifier, claims.BootKID)
	state.SetRegistered(true)
	if err := state.HandleResponse(claims.KeyHash, claims.WorkspaceID, &Response{Token: &token, LeaseStatus: "active"}, now); err == nil {
		t.Fatal("flag-off state accepted authoritative grant")
	}
	state.SetLocalAdmission(true)
	if err := state.HandleResponse(claims.KeyHash, claims.WorkspaceID, &Response{Token: &token, LeaseStatus: "active"}, now); err != nil {
		t.Fatalf("flag-on state rejected authoritative grant: %v", err)
	}
}

func TestShadowStateSequentialDepletionEchoesPreRequestState(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	issuer, verifier := newTestIssuer(t, now)
	state := NewShadowState(verifier, "boot-1")
	state.SetRegistered(true)
	token := stateTestToken(t, issuer, now, 1, 9, "123e4567-e89b-42d3-a456-426614174001")
	if err := state.HandleResponse("key-1", "ws-1", &Response{Token: &token, LeaseStatus: "active"}, now); err != nil {
		t.Fatal(err)
	}
	request := EstimateRequest{Model: "model-1", RouteType: "chat.completions", Region: "us-central1", EstimatedInputTokens: 1}
	for index, wantRemaining := range []int64{9, 6, 3} {
		echo := state.BeforeRequest("key-1", request, now.Add(time.Duration(index)*time.Second))
		if echo.State != "active" || echo.RemainingMicro == nil || *echo.RemainingMicro != wantRemaining || echo.WouldAdmit == nil || !*echo.WouldAdmit {
			t.Fatalf("request %d echo = %#v, want active pre-request remaining %d", index+1, echo, wantRemaining)
		}
	}
	echo := state.BeforeRequest("key-1", request, now.Add(4*time.Second))
	if echo.State != "exhausted" || echo.RemainingMicro == nil || *echo.RemainingMicro != 0 || echo.WouldAdmit == nil || *echo.WouldAdmit {
		t.Fatalf("post-depletion echo = %#v", echo)
	}
}

// Mutation target (b): removing the strict generation comparison makes the
// final gen=2 response replace the dead gen=3 grant and this test fail.
func TestShadowStateRejectsOutOfOrderGenerationAfterDepletion(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	issuer, verifier := newTestIssuer(t, now)
	state := NewShadowState(verifier, "boot-1")
	state.SetRegistered(true)
	request := EstimateRequest{Model: "model-1", RouteType: "chat.completions", Region: "us-central1", EstimatedInputTokens: 1}

	gen1 := stateTestToken(t, issuer, now, 1, 3, "123e4567-e89b-42d3-a456-426614174001")
	if err := state.HandleResponse("key-1", "ws-1", &Response{Token: &gen1, LeaseStatus: "active"}, now); err != nil {
		t.Fatal(err)
	}
	_ = state.BeforeRequest("key-1", request, now)

	gen3 := stateTestToken(t, issuer, now, 3, 3, "123e4567-e89b-42d3-a456-426614174003")
	if err := state.HandleResponse("key-1", "ws-1", &Response{Token: &gen3, LeaseStatus: "active"}, now); err != nil {
		t.Fatal(err)
	}
	_ = state.BeforeRequest("key-1", request, now)

	gen2 := stateTestToken(t, issuer, now, 2, 30, "123e4567-e89b-42d3-a456-426614174002")
	if err := state.HandleResponse("key-1", "ws-1", &Response{Token: &gen2, LeaseStatus: "active"}, now); err != nil {
		t.Fatal(err)
	}
	echo := state.BeforeRequest("key-1", request, now)
	if echo.LeaseID == nil || *echo.LeaseID != "123e4567-e89b-42d3-a456-426614174003" || echo.State != "exhausted" {
		t.Fatalf("out-of-order generation replaced newer grant: %#v", echo)
	}
}

func TestShadowStateRetainsLiveGrantUntilTerminal(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	issuer, verifier := newTestIssuer(t, now)
	state := NewShadowState(verifier, "boot-1")
	state.SetRegistered(true)
	request := EstimateRequest{Model: "model-1", RouteType: "chat.completions", Region: "us-central1", EstimatedInputTokens: 1}
	lease1ID := "123e4567-e89b-42d3-a456-426614174001"
	lease2ID := "123e4567-e89b-42d3-a456-426614174002"
	gen1 := stateTestToken(t, issuer, now, 1, 9, lease1ID)
	gen2 := stateTestToken(t, issuer, now, 2, 12, lease2ID)
	if err := state.HandleResponse("key-1", "ws-1", &Response{Token: &gen1, LeaseStatus: "active"}, now); err != nil {
		t.Fatal(err)
	}
	if err := state.HandleResponse("key-1", "ws-1", &Response{Token: &gen2, LeaseStatus: "active"}, now); err != nil {
		t.Fatal(err)
	}
	echo := state.BeforeRequest("key-1", request, now)
	if echo.LeaseID == nil || *echo.LeaseID != lease1ID || echo.RemainingMicro == nil || *echo.RemainingMicro != 9 {
		t.Fatalf("live grant was replaced by newer generation: %#v", echo)
	}
	if err := state.HandleResponse("key-1", "ws-1", &Response{Token: &gen1, LeaseStatus: "terminal"}, now); err != nil {
		t.Fatal(err)
	}
	if err := state.HandleResponse("key-1", "ws-1", &Response{Token: &gen2, LeaseStatus: "active"}, now); err != nil {
		t.Fatal(err)
	}
	echo = state.BeforeRequest("key-1", request, now)
	if echo.LeaseID == nil || *echo.LeaseID != lease2ID || echo.RemainingMicro == nil || *echo.RemainingMicro != 12 {
		t.Fatalf("terminal grant was not replaced by newer generation: %#v", echo)
	}
}
