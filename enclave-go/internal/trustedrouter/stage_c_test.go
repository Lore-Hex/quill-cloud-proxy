package trustedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func stageCAdmissionClient(
	t *testing.T,
	responseFixture string,
	status int,
	inspect func(*http.Request, []byte),
) (*Client, *receipt.Signer, *spendlease.Claims) {
	t.Helper()
	signer := stageCFixtureSigner(t)
	var claims spendlease.Claims
	if err := json.Unmarshal(bytes.TrimSpace(stageCFixture(t, "authoritative_lease_payload.json")), &claims); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(spendlease.IssuerConfig{Version: 1, Keys: []spendlease.IssuerKey{{
		KID: signer.Kid(), JWK: spendlease.JWK{KeyType: "OKP", Curve: "Ed25519", X: signer.JWK().X},
		NotBefore: claims.IssuedAt - 60, NotAfter: claims.ExpiresAt + 60,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := spendlease.NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		if inspect != nil {
			inspect(request, body)
		}
		return &http.Response{
			StatusCode: status, Header: make(http.Header), Request: request,
			Body: io.NopCloser(bytes.NewReader(stageCFixture(t, responseFixture))),
		}, nil
	})})
	client.region = "us-central1"
	client.ConfigureSpendLeaseShadow(signer, verifier)
	client.ConfigureSpendLeaseLocalAdmission(true)
	client.spendLease.state.SetRegistered(true)
	header := struct {
		Algorithm string `json:"alg"`
		KID       string `json:"kid"`
		Type      string `json:"typ"`
	}{Algorithm: "EdDSA", KID: signer.Kid(), Type: spendlease.JWSType}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	token := stageCSignCompactInputs(t, signer, headerJSON, payloadJSON)
	now := time.UnixMilli(2_000_000_005_000)
	if err := client.spendLease.state.HandleResponse(
		claims.KeyHash, claims.WorkspaceID,
		&spendlease.Response{Token: &token, LeaseStatus: "active"}, now,
	); err != nil {
		t.Fatal(err)
	}
	return client, signer, &claims
}

func fixedStageCContext() context.Context {
	invocation := &authorizationInvocation{nonce: "00112233445566778899aabbccddeeff"}
	invocation.once.Do(func() {})
	ctx := context.WithValue(context.Background(), authorizationInvocationContextKey{}, invocation)
	ctx, err := WithAPIKeyLookupHash(ctx, stageCFixtureKeyHash)
	if err != nil {
		panic(err)
	}
	return ctx
}

type failingStageCAdmissionSigner struct {
	*receipt.Signer
}

func (f failingStageCAdmissionSigner) SignMessage([]byte) ([]byte, error) {
	return nil, errors.New("fixture signing unavailable")
}

func TestStageCReceiptSigningFailureFallsBackToSynchronousAuthorize(t *testing.T) {
	client, signer, _ := stageCAdmissionClient(t, "admission_accepted_response.json", http.StatusOK, nil)
	client.spendLease.signer = failingStageCAdmissionSigner{Signer: signer}
	plan, err := client.PrepareSpendLeaseAdmission(
		fixedStageCContext(), "sk-stage-c-fixture", stageCFixtureRequest(), "chat.completions", time.UnixMilli(2_000_000_005_000),
	)
	if err != nil || plan != nil {
		t.Fatalf("signing failure did not fall back: plan=%#v err=%v", plan, err)
	}
}

func TestStageCReserveUsesPinnedReceiptBodyAndReturnsBoundMarker(t *testing.T) {
	client, _, claims := stageCAdmissionClient(t, "admission_accepted_response.json", http.StatusOK, func(request *http.Request, body []byte) {
		wantBody := stageCFixture(t, "receipt_bearing_authorize_request.json")
		if !bytes.Equal(body, wantBody) {
			t.Fatalf("reserve body drift\ngot:  %s\nwant: %s", body, wantBody)
		}
		if got := request.Header.Get(spendlease.BootAuthHeader); got == "" {
			t.Fatal("reserve request omitted boot auth")
		}
	})
	req := stageCFixtureRequest()
	now := time.UnixMilli(2_000_000_005_000)
	plan, err := client.PrepareSpendLeaseAdmission(fixedStageCContext(), "sk-stage-c-fixture", req, "chat.completions", now)
	if err != nil || plan == nil || plan.Local == nil || len(plan.Local.RouteCandidates) != 1 {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	resolved, marked, err := client.ReserveSpendLeaseAdmission(fixedStageCContext(), plan, req)
	if err != nil || !marked || resolved.AuthorizationID != "gwa-stage-c-fixture" || resolved.SpendLeaseRemainingMicro == nil {
		t.Fatalf("resolved=%#v marked=%t err=%v", resolved, marked, err)
	}
	if *resolved.SpendLeaseRemainingMicro >= claims.CapMicro {
		t.Fatalf("ledger remaining did not decrease: %d", *resolved.SpendLeaseRemainingMicro)
	}
}

func TestStageCReserveRetriesIdenticalReceiptBytesAndBootProof(t *testing.T) {
	client, _, _ := stageCAdmissionClient(t, "admission_accepted_response.json", http.StatusOK, nil)
	client.authorizeRetry = retryPolicy{attempts: 2, totalBudget: spendlease.ReserveBudget, sleep: func(context.Context, time.Duration) error { return nil }}
	var bodies [][]byte
	var proofs []string
	attempt := 0
	client.httpc.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		bodies = append(bodies, append([]byte(nil), body...))
		proofs = append(proofs, request.Header.Get(spendlease.BootAuthHeader))
		attempt++
		status := http.StatusServiceUnavailable
		responseBody := []byte(`{"error":{"message":"retry","type":"service_unavailable"}}`)
		if attempt == 2 {
			status = http.StatusOK
			responseBody = stageCFixture(t, "admission_accepted_response.json")
		}
		return &http.Response{
			StatusCode: status, Header: make(http.Header), Request: request,
			Body: io.NopCloser(bytes.NewReader(responseBody)),
		}, nil
	})
	req := stageCFixtureRequest()
	plan, err := client.PrepareSpendLeaseAdmission(
		fixedStageCContext(), "sk-stage-c-fixture", req, "chat.completions", time.UnixMilli(2_000_000_005_000),
	)
	if err != nil || plan == nil {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	if _, marked, reserveErr := client.ReserveSpendLeaseAdmission(fixedStageCContext(), plan, req); reserveErr != nil || !marked {
		t.Fatalf("marked=%t err=%v", marked, reserveErr)
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || len(proofs) != 2 || proofs[0] == "" || proofs[0] != proofs[1] {
		t.Fatalf("retry drift: bodies=%q proofs=%q", bodies, proofs)
	}
}

func TestStageCAcceptedMarkerCannotAuthorizeDifferentSnapshotRoute(t *testing.T) {
	body := bytes.Replace(
		stageCFixture(t, "admission_accepted_response.json"),
		[]byte(`"upstream_model":"claude-haiku-4-5-20251001"`),
		[]byte(`"upstream_model":"different-model"`),
		1,
	)
	client, _, _ := stageCAdmissionClient(t, "admission_accepted_response.json", http.StatusOK, nil)
	client.httpc.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Request: request,
			Body: io.NopCloser(bytes.NewReader(body)),
		}, nil
	})
	req := stageCFixtureRequest()
	plan, err := client.PrepareSpendLeaseAdmission(
		fixedStageCContext(), "sk-stage-c-fixture", req, "chat.completions", time.UnixMilli(2_000_000_005_000),
	)
	if err != nil || plan == nil {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	_, marked, reserveErr := client.ReserveSpendLeaseAdmission(fixedStageCContext(), plan, req)
	var controlErr *ControlPlaneError
	if !errors.As(reserveErr, &controlErr) || marked || controlErr.Reason != "receipt_invalid" {
		t.Fatalf("marked=%t error=%#v", marked, reserveErr)
	}
}

func TestStageCCapacityResponseDisablesFurtherAdmission(t *testing.T) {
	client, _, _ := stageCAdmissionClient(t, "admission_rejected_capacity.json", http.StatusConflict, nil)
	req := stageCFixtureRequest()
	plan, err := client.PrepareSpendLeaseAdmission(fixedStageCContext(), "sk-stage-c-fixture", req, "chat.completions", time.UnixMilli(2_000_000_005_000))
	if err != nil || plan == nil {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	resolved, marked, err := client.ReserveSpendLeaseAdmission(fixedStageCContext(), plan, req)
	if err == nil || marked {
		t.Fatalf("resolved=%#v marked=%t err=%v", resolved, marked, err)
	}
	req.IdempotencyKey = "another-idempotency-key"
	next, nextErr := client.PrepareSpendLeaseAdmission(fixedStageCContext(), "sk-stage-c-fixture", req, "chat.completions", time.UnixMilli(2_000_000_006_000))
	if nextErr != nil || next != nil {
		t.Fatalf("disabled grant admitted again: plan=%#v err=%v", next, nextErr)
	}
}

func TestStageCPolicyEligibilityFailsClosed(t *testing.T) {
	base := stageCFixtureRequest()
	if _, ok := routingPolicyHash(base, "chat.completions", "us-central1"); !ok {
		t.Fatal("fixture unexpectedly ineligible")
	}
	for _, mutate := range []func(*qtypes.OpenAIChatRequest){
		func(req *qtypes.OpenAIChatRequest) { req.Models = []string{"openai/gpt-4o-mini"} },
		func(req *qtypes.OpenAIChatRequest) { req.Provider.Sort = "price" },
		func(req *qtypes.OpenAIChatRequest) { req.Provider.Usage = "byok" },
		func(req *qtypes.OpenAIChatRequest) { req.Model = "trustedrouter/auto" },
		func(req *qtypes.OpenAIChatRequest) { req.ResponseModel = "trustedrouter/custom-wrapper" },
		func(req *qtypes.OpenAIChatRequest) { req.AdditionalCostReservationMicrodollars = 1 },
	} {
		req := stageCFixtureRequest()
		mutate(req)
		if _, ok := routingPolicyHash(req, "chat.completions", "us-central1"); ok {
			t.Fatalf("ineligible request accepted: %#v", req)
		}
	}
}

func TestStageCClosedRejectionFixturesDecodeAndApplyKillReasons(t *testing.T) {
	reasons := []string{
		"receipt_invalid", "boot_not_accepted", "boot_mismatch", "lease_not_open", "window", "policy_mismatch",
		"estimate_mismatch", "capacity", "hold_refused", "scope_conflict", "reuse_lost", "not_accepting",
	}
	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			client, _, _ := stageCAdmissionClient(t, "admission_rejected_"+reason+".json", http.StatusConflict, nil)
			req := stageCFixtureRequest()
			plan, err := client.PrepareSpendLeaseAdmission(
				fixedStageCContext(), "sk-stage-c-fixture", req, "chat.completions", time.UnixMilli(2_000_000_005_000),
			)
			if err != nil || plan == nil {
				t.Fatalf("plan=%#v err=%v", plan, err)
			}
			_, marked, reserveErr := client.ReserveSpendLeaseAdmission(fixedStageCContext(), plan, req)
			var controlErr *ControlPlaneError
			if !errors.As(reserveErr, &controlErr) || controlErr.Type != "admission_rejected" || controlErr.Reason != reason || marked {
				t.Fatalf("marked=%t error=%#v", marked, reserveErr)
			}
			if reason == "boot_not_accepted" || reason == "not_accepting" || reason == "capacity" {
				req.IdempotencyKey = "next-" + reason
				next, nextErr := client.PrepareSpendLeaseAdmission(
					fixedStageCContext(), "sk-stage-c-fixture", req, "chat.completions", time.UnixMilli(2_000_000_006_000),
				)
				if nextErr != nil || next != nil {
					t.Fatalf("kill reason admitted another request: plan=%#v err=%v", next, nextErr)
				}
			}
		})
	}
}
