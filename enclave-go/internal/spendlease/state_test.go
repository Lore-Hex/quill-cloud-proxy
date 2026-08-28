package spendlease

import (
	"encoding/base64"
	"testing"
	"time"
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
