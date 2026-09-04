package trustedrouter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const stageCFixtureKeyHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestStageCFixtureSetUsesRouterCanonicalNames(t *testing.T) {
	want := []string{
		"admission_accepted_response.json",
		"admission_receipt_compact.jws",
		"admission_receipt_ed25519_seed.hex",
		"admission_receipt_payload.json",
		"admission_receipt_protected_header.json",
		"admission_receipt_verification_jwk.json",
		"admission_rejected_boot_mismatch.json",
		"admission_rejected_boot_not_accepted.json",
		"admission_rejected_capacity.json",
		"admission_rejected_estimate_mismatch.json",
		"admission_rejected_hold_refused.json",
		"admission_rejected_lease_not_open.json",
		"admission_rejected_not_accepting.json",
		"admission_rejected_policy_mismatch.json",
		"admission_rejected_receipt_invalid.json",
		"admission_rejected_reuse_lost.json",
		"admission_rejected_scope_conflict.json",
		"admission_rejected_window.json",
		"authoritative_lease_compact.jws",
		"authoritative_lease_payload.json",
		"authoritative_lease_protected_header.json",
		"normalized_routing_inputs.json",
		"normalized_routing_inputs.sha256",
		"origin_main/authorize_response.json",
		"origin_main/gateway_authorization_insert.sql",
		"origin_main/lease_claims.json",
		"origin_main/origin_main_commit.txt",
		"receipt_bearing_authorize_boot_auth.txt",
		"receipt_bearing_authorize_request.json",
	}
	var got []string
	err := filepath.Walk(filepath.Join("testdata", "stage_c"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			relative, err := filepath.Rel(filepath.Join("testdata", "stage_c"), path)
			if err != nil {
				return err
			}
			got = append(got, filepath.ToSlash(relative))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !equalStrings(got, want) {
		t.Fatalf("Stage-C fixture names = %q, want %q", got, want)
	}
}

func TestStageCCompactJWSFixturesReproduceFromRouterSeed(t *testing.T) {
	signer := stageCFixtureSigner(t)

	var receiptClaims spendlease.AdmissionReceiptClaims
	if err := json.Unmarshal(stageCFixture(t, "admission_receipt_payload.json"), &receiptClaims); err != nil {
		t.Fatal(err)
	}
	receiptToken, err := spendlease.SignAdmissionReceipt(signer, receiptClaims)
	if err != nil {
		t.Fatal(err)
	}
	assertFixtureBytes(t, "admission_receipt_compact.jws", []byte(receiptToken))
	receiptParts, err := receipt.ParseJWS([]byte(receiptToken))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receiptParts.ProtectedJSON, stageCFixture(t, "admission_receipt_protected_header.json")) ||
		!bytes.Equal(receiptParts.PayloadJSON, stageCFixture(t, "admission_receipt_payload.json")) {
		t.Fatal("admission receipt did not preserve the canonical protected header and payload")
	}

	leaseToken := stageCSignCompactInputs(
		t,
		signer,
		stageCFixture(t, "authoritative_lease_protected_header.json"),
		stageCFixture(t, "authoritative_lease_payload.json"),
	)
	assertFixtureBytes(t, "authoritative_lease_compact.jws", []byte(leaseToken))
}

func TestStageCAdmissionReceiptVerifiesWithRouterJWK(t *testing.T) {
	parts, err := receipt.ParseJWS(stageCFixture(t, "admission_receipt_compact.jws"))
	if err != nil {
		t.Fatal(err)
	}
	var jwk spendlease.JWK
	if err := json.Unmarshal(stageCFixture(t, "admission_receipt_verification_jwk.json"), &jwk); err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("verification JWK: key length=%d err=%v", len(publicKey), err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), parts.SigningInput, parts.Signature) {
		t.Fatal("canonical admission receipt failed Ed25519 verification")
	}
}

func TestStageCAuthoritativeLeaseVerifiesWithRouterJWK(t *testing.T) {
	lease, err := stageCLeaseVerifier(t).VerifyAt(
		string(stageCFixture(t, "authoritative_lease_compact.jws")),
		time.Unix(2_000_000_005, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := lease.Claims.Cohort, "credits-chat-v1"; got != want {
		t.Fatalf("canonical lease cohort = %q, want %q", got, want)
	}
	if !lease.Claims.Authoritative {
		t.Fatal("canonical lease is not authoritative")
	}
	if !lease.Claims.LocalAdmissionAllowed {
		t.Fatal("canonical lease does not allow local admission")
	}
	if got, want := lease.Claims.RoutingPolicyHash, strings.TrimSpace(string(stageCFixture(t, "normalized_routing_inputs.sha256"))); got != want {
		t.Fatalf("canonical lease routing policy hash = %q, want %q", got, want)
	}
	if got, want := lease.Claims.BootKID, "Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw"; got != want {
		t.Fatalf("canonical lease boot kid = %q, want %q", got, want)
	}
}

func TestStageCAuthoritativeLeaseWithoutCohortIsRejectedAsInvalidGrantClaims(t *testing.T) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(stageCFixture(t, "authoritative_lease_payload.json"), &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["cohort"]; !ok {
		t.Fatal("canonical lease payload omitted cohort")
	}
	delete(payload, "cohort")
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	token := stageCSignCompactInputs(
		t,
		stageCFixtureSigner(t),
		stageCFixture(t, "authoritative_lease_protected_header.json"),
		payloadJSON,
	)
	_, err = stageCLeaseVerifier(t).VerifyAt(
		token,
		time.Unix(2_000_000_005, 0),
	)
	const want = "spendlease: invalid grant claims"
	if err == nil || err.Error() != want {
		t.Fatalf("cohort-less lease verifier error = %v, want %q", err, want)
	}
}

func TestStageCNormalizedRoutingInputsAndHashMatchRouterBytes(t *testing.T) {
	got, eligible := normalizedRoutingInputs(stageCFixtureRequest(), "chat.completions", "us-central1")
	if !eligible {
		t.Fatal("canonical routing input is not eligible")
	}
	assertFixtureBytes(t, "normalized_routing_inputs.json", got)
	digest := sha256.Sum256(got)
	if gotHash := hex.EncodeToString(digest[:]); gotHash != string(stageCFixture(t, "normalized_routing_inputs.sha256")) {
		t.Fatalf("normalized routing hash = %s", gotHash)
	}
}

func TestStageCAuthorizeResponseFixturesDecodeWithEnclaveTypes(t *testing.T) {
	var accepted struct {
		Data Authorization `json:"data"`
	}
	if err := json.Unmarshal(stageCFixture(t, "admission_accepted_response.json"), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Data.AuthorizationID != "gwa-stage-c-fixture" || accepted.Data.SpendLeaseAdmission == nil ||
		!accepted.Data.SpendLeaseAdmission.Accepted || accepted.Data.SpendLease == nil ||
		accepted.Data.SpendLease.RemainingMicro == nil || *accepted.Data.SpendLease.RemainingMicro != 999366 {
		t.Fatalf("accepted response decoded incompletely: %#v", accepted.Data)
	}

	reasons := []string{
		"receipt_invalid", "boot_not_accepted", "boot_mismatch", "lease_not_open", "window", "policy_mismatch",
		"estimate_mismatch", "capacity", "hold_refused", "scope_conflict", "reuse_lost", "not_accepting",
	}
	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			response := &http.Response{
				StatusCode: http.StatusConflict,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(stageCFixture(t, "admission_rejected_"+reason+".json"))),
			}
			controlErr, ok := decodeControlPlaneError(spendlease.AuthorizePath, response).(*ControlPlaneError)
			if !ok || controlErr.Type != "admission_rejected" || controlErr.Reason != reason {
				t.Fatalf("decoded rejection = %#v", controlErr)
			}
		})
	}
}

func TestStageCReceiptBearingAuthorizeEmitsEnclaveCanonicalBytes(t *testing.T) {
	signer := stageCFixtureSigner(t)
	var sent []byte
	var sentBootAuth string
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		sent, _ = io.ReadAll(request.Body)
		sentBootAuth = request.Header.Get(spendlease.BootAuthHeader)
		if sentBootAuth == "" {
			t.Fatal("receipt-bearing authorize omitted boot auth")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Request:    request,
			Body:       io.NopCloser(bytes.NewReader(stageCFixture(t, "admission_accepted_response.json"))),
		}, nil
	})})
	client.region = "us-central1"
	client.stageDBootSigner = signer
	req := stageCFixtureRequest()
	body := chatAuthorizeBody(client, stageCFixtureKeyHash, req.IdempotencyKey, req, "chat.completions")
	admission := &spendlease.Admission{Receipt: strings.TrimSpace(string(stageCFixture(t, "admission_receipt_compact.jws")))}
	got, _, err := client.authorizeAtDecodeSeamWithAdmission(
		fixedStageCContext(), stageCFixtureKeyHash, body, spendLeaseRequestForChat(client.region, "chat.completions", req), admission,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthorizationID != "gwa-stage-c-fixture" {
		t.Fatalf("authorization id = %q", got.AuthorizationID)
	}

	requestPath := filepath.Join("testdata", "stage_c", "receipt_bearing_authorize_request.json")
	bootAuthPath := filepath.Join("testdata", "stage_c", "receipt_bearing_authorize_boot_auth.txt")
	if err := os.WriteFile(requestPath, sent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bootAuthPath, []byte(sentBootAuth), 0o600); err != nil {
		t.Fatal(err)
	}
	fmt.Println(requestPath)
	fmt.Println(bootAuthPath)

	reSigned, err := spendlease.SignAuthorize(
		stageCFixtureSigner(t),
		http.MethodPost,
		spendlease.AuthorizePath,
		stageCFixture(t, "receipt_bearing_authorize_request.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	want := string(stageCFixture(t, "receipt_bearing_authorize_boot_auth.txt"))
	if reSigned.HeaderValue() != want {
		t.Fatalf("re-signed boot auth = %q, want emitted header %q", reSigned.HeaderValue(), want)
	}
}

func stageCFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "stage_c", name))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func stageCFixtureSigner(t *testing.T) *receipt.Signer {
	t.Helper()
	seed, err := hex.DecodeString(strings.TrimSpace(string(stageCFixture(t, "admission_receipt_ed25519_seed.hex"))))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("fixture seed: length=%d err=%v", len(seed), err)
	}
	signer, err := receipt.NewSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func stageCLeaseVerifier(t *testing.T) *spendlease.Verifier {
	t.Helper()
	var jwk spendlease.JWK
	if err := json.Unmarshal(stageCFixture(t, "admission_receipt_verification_jwk.json"), &jwk); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(spendlease.IssuerConfig{Version: 1, Keys: []spendlease.IssuerKey{{
		KID: "Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw", JWK: jwk,
		NotBefore: 1_999_999_940, NotAfter: 2_000_000_120,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := spendlease.NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func stageCFixtureRequest() *qtypes.OpenAIChatRequest {
	providerFallbacks := false
	return &qtypes.OpenAIChatRequest{
		Model: "anthropic/claude-haiku-4.5",
		Messages: []qtypes.OpenAIChatMessage{{
			Role:    "user",
			Content: strings.Repeat("x", 384),
		}},
		MaxTokens:      intPointer(100),
		IdempotencyKey: "stage-c-fixture-idempotency",
		Provider: &qtypes.ProviderRouting{
			Only:           qtypes.StringList{"anthropic"},
			Usage:          "credits",
			AllowFallbacks: &providerFallbacks,
			DataCollection: "deny",
		},
	}
}

func stageCSignCompactInputs(t *testing.T, signer *receipt.Signer, protectedJSON, payloadJSON []byte) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(protectedJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	signature, err := signer.SignMessage([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func assertFixtureBytes(t *testing.T, name string, got []byte) {
	t.Helper()
	want := stageCFixture(t, name)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs\ngot:  %s\nwant: %s", name, got, want)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func intPointer(value int) *int { return &value }
