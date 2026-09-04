package trustedrouter

import (
	"bytes"
	"context"
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
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const stageCFixtureSeedHex = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"

type stageCLeaseHeader struct {
	Algorithm string         `json:"alg"`
	Type      string         `json:"typ"`
	KID       string         `json:"kid"`
	JWK       spendlease.JWK `json:"jwk"`
}

func TestStageCLiteralFixturesMatchDeterministicSerializers(t *testing.T) {
	fixtures := stageCFixtures(t)
	if os.Getenv("STAGE_C_UPDATE_FIXTURES") == "1" {
		dir := filepath.Join("testdata", "stage_c")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range fixtures {
			if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	if os.Getenv("STAGE_C_PRINT_FIXTURES") == "1" {
		names := make([]string, 0, len(fixtures))
		for name := range fixtures {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Printf("%s\t%s\n", name, base64.StdEncoding.EncodeToString(fixtures[name]))
		}
		return
	}
	for name, want := range fixtures {
		got, err := os.ReadFile(filepath.Join("testdata", "stage_c", name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s differs\ngot:  %s\nwant: %s", name, got, want)
		}
	}
}

func TestStageCFlagOffMatchesRecordedAuthorizeGoldens(t *testing.T) {
	for _, routeType := range []string{"chat.completions", "responses"} {
		fixtureName := "flag_off_chat_authorize.json"
		if routeType == "responses" {
			fixtureName = "flag_off_responses_authorize.json"
		}
		want := bytes.TrimSuffix(stageCFixture(t, fixtureName), []byte{'\n'})
		var got []byte
		client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			got, _ = io.ReadAll(request.Body)
			if request.Header.Get(spendlease.BootAuthHeader) != "" {
				t.Fatal("flag-off request carried boot auth")
			}
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header), Request: request,
				Body: io.NopCloser(bytes.NewBufferString(`{"data":{"authorization_id":"gwa_sync_fixture"}}`)),
			}, nil
		})})
		client.region = "us-central1"
		req := stageCFixtureRequest()
		invocation := &authorizationInvocation{nonce: "00112233445566778899aabbccddeeff"}
		invocation.once.Do(func() {})
		ctx := context.WithValue(context.Background(), authorizationInvocationContextKey{}, invocation)
		if _, err := client.AuthorizeWithRoute(ctx, "sk-stage-c-fixture", req, routeType); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s flag-off wire drift\ngot:  %s\nwant: %s", routeType, got, want)
		}
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

func stageCFixtureRequest() *qtypes.OpenAIChatRequest {
	providerFallbacks := false
	return &qtypes.OpenAIChatRequest{
		Model: "openai/gpt-4o-mini", Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "fixture"}},
		Stream: true, MaxTokens: intPointer(64), IdempotencyKey: "stage-c-idempotency-key",
		Provider: &qtypes.ProviderRouting{
			Only: qtypes.StringList{"openai"}, Usage: "credits", AllowFallbacks: &providerFallbacks,
			DataCollection: "deny", ZDR: boolPointer(true),
		},
	}
}

func stageCFixtures(t *testing.T) map[string][]byte {
	t.Helper()
	seed, err := hex.DecodeString(stageCFixtureSeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("fixture seed: %v", err)
	}
	signer, err := receipt.NewSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	public, err := base64.RawURLEncoding.DecodeString(signer.JWK().X)
	if err != nil {
		t.Fatal(err)
	}
	issuerJWK := spendlease.JWK{KeyType: "OKP", Curve: "Ed25519", X: signer.JWK().X}

	req := stageCFixtureRequest()
	client := &Client{region: "us-central1"}
	policyJSON, eligible := normalizedRoutingInputs(req, "chat.completions", client.region)
	if !eligible {
		t.Fatal("fixture routing input is not eligible")
	}
	policyDigest := sha256.Sum256(policyJSON)
	policyHash := hex.EncodeToString(policyDigest[:])

	claims := spendlease.Claims{
		Version: 1, Type: spendlease.JWSType, Authoritative: true, LocalAdmissionAllowed: true,
		RoutingPolicyHash: policyHash, LeaseID: "123e4567-e89b-42d3-a456-426614174066",
		KeyHash: lookupHash("sk-stage-c-fixture"), WorkspaceID: "ws_stage_c_fixture", Cohort: spendlease.Cohort,
		CapMicro: 10000, Generation: 7, IssuedAt: 2_000_000_000, ExpiresAt: 2_000_000_060,
		BootKID: signer.Kid(), Catalog: spendlease.Catalog{Version: "catalog-stage-c-1", Candidates: []spendlease.Candidate{{
			EndpointID: "openai/gpt-4o-mini@openai/prepaid", Model: "openai/gpt-4o-mini", UpstreamModel: "gpt-4o-mini",
			Provider: "openai", UsageType: "Credits", WaferZDRRequired: false, Region: "us-central1",
			RouteType: "chat.completions", ServiceTier: "", InputPriceMicroPerMTok: 150000,
			OutputPriceMicroPerMTok: 600000, RequestPriceMicro: 0, CacheReadMicroPerMTok: 75000,
			CacheWriteMicroPerMTok: 0,
		}}},
	}
	leaseHeaderJSON := stageCMustJSON(t, stageCLeaseHeader{
		Algorithm: "EdDSA", Type: spendlease.JWSType, KID: signer.Kid(), JWK: issuerJWK,
	})
	leasePayloadJSON := stageCMustJSON(t, claims)
	leaseInput := base64.RawURLEncoding.EncodeToString(leaseHeaderJSON) + "." + base64.RawURLEncoding.EncodeToString(leasePayloadJSON)
	leaseSignature, err := signer.SignMessage([]byte(leaseInput))
	if err != nil {
		t.Fatal(err)
	}
	leaseToken := leaseInput + "." + base64.RawURLEncoding.EncodeToString(leaseSignature)

	estimateRequest := spendLeaseRequestForChat(client.region, "chat.completions", req)
	estimate, err := spendlease.Estimate(claims.Catalog, estimateRequest)
	if err != nil || estimate == nil {
		t.Fatalf("fixture estimate=%v err=%v", estimate, err)
	}
	receiptClaims := spendlease.AdmissionReceiptClaims{
		Version: 1, LeaseID: claims.LeaseID, Generation: claims.Generation,
		KeyHash: claims.KeyHash, WorkspaceID: claims.WorkspaceID, BootKID: claims.BootKID,
		IdempotencyKeySHA256: spendlease.IdempotencyKeyHash(req.IdempotencyKey), RoutingPolicyHash: policyHash,
		EnclaveEstimateMicro: *estimate, RemainingAfterMicro: claims.CapMicro - *estimate,
		AdmittedAtMS: 2_000_000_001_123,
	}
	admissionReceipt, err := spendlease.SignAdmissionReceipt(signer, receiptClaims)
	if err != nil {
		t.Fatal(err)
	}
	receiptParts, err := receipt.ParseJWS([]byte(admissionReceipt))
	if err != nil {
		t.Fatal(err)
	}

	body := chatAuthorizeBody(client, claims.KeyHash, req.IdempotencyKey, req, "chat.completions")
	body["invocation_nonce"] = "00112233445566778899aabbccddeeff"
	flagOffChatBody := stageCMustJSON(t, body)
	flagOffResponses := chatAuthorizeBody(client, claims.KeyHash, req.IdempotencyKey, req, "responses")
	flagOffResponses["invocation_nonce"] = "00112233445566778899aabbccddeeff"
	flagOffResponsesBody := stageCMustJSON(t, flagOffResponses)
	body["spend_lease_echo"] = spendlease.Echo{
		LeaseID: &claims.LeaseID, State: "active", RemainingMicro: int64PointerFixture(claims.CapMicro),
		EnclaveEstimateMicro: estimate, CatalogVersion: &claims.Catalog.Version, WouldAdmit: boolPointer(true),
	}
	body["spend_lease_admission"] = admissionReceipt
	authorizeBody := stageCMustJSON(t, body)
	bootAuth, err := spendlease.SignAuthorize(signer, http.MethodPost, spendlease.AuthorizePath, authorizeBody)
	if err != nil {
		t.Fatal(err)
	}
	receiptHash := spendlease.AdmissionReceiptHash(admissionReceipt)
	accepted := []byte(fmt.Sprintf(`{"data":{"authorization_id":"gwa_stage_c_fixture","invocation_nonce":"00112233445566778899aabbccddeeff","workspace_id":"%s","api_key_hash":"%s","model":"openai/gpt-4o-mini","upstream_model":"gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","provider_name":"OpenAI","region":"us-central1","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[{"endpoint_id":"openai/gpt-4o-mini@openai/prepaid","model":"openai/gpt-4o-mini","upstream_model":"gpt-4o-mini","provider":"openai","provider_name":"OpenAI","wafer_zdr_required":false,"usage_type":"Credits"}],"spend_lease_remaining_micro":%d,"spend_lease_admission":{"accepted":true,"receipt_hash":"%s"}}}`, claims.WorkspaceID, claims.KeyHash, claims.CapMicro-*estimate, receiptHash))
	unmarked := []byte(fmt.Sprintf(`{"data":{"authorization_id":"gwa_stage_c_unmarked","invocation_nonce":"00112233445566778899aabbccddeeff","workspace_id":"%s","api_key_hash":"%s","model":"openai/gpt-4o-mini","upstream_model":"gpt-4o-mini","endpoint_id":"openai/gpt-4o-mini@openai/prepaid","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]}}`, claims.WorkspaceID, claims.KeyHash))

	fixtures := map[string][]byte{
		"ed25519_seed.hex":                   []byte(stageCFixtureSeedHex),
		"verification_jwk.json":              stageCMustJSON(t, signer.JWK()),
		"authoritative_lease_protected.json": leaseHeaderJSON,
		"authoritative_lease_payload.json":   leasePayloadJSON,
		"authoritative_lease.jws":            []byte(leaseToken),
		"routing_policy_input.json":          policyJSON,
		"routing_policy_hash.txt":            []byte(policyHash),
		"admission_receipt_protected.json":   receiptParts.ProtectedJSON,
		"admission_receipt_payload.json":     receiptParts.PayloadJSON,
		"admission_receipt.jws":              []byte(admissionReceipt),
		"authorize_request.json":             authorizeBody,
		"authorize_boot_auth.txt":            []byte(bootAuth.HeaderValue()),
		"authorize_response_accepted.json":   accepted,
		"authorize_response_unmarked.json":   unmarked,
		"flag_off_chat_authorize.json":       flagOffChatBody,
		"flag_off_responses_authorize.json":  flagOffResponsesBody,
	}
	for _, reason := range []string{
		"receipt_invalid", "boot_not_accepted", "boot_mismatch", "lease_not_open", "window", "policy_mismatch",
		"estimate_mismatch", "capacity", "hold_refused", "scope_conflict", "reuse_lost", "not_accepting",
	} {
		fixtures["authorize_response_rejection_"+reason+".json"] = []byte(fmt.Sprintf(
			`{"error":{"message":"Spend lease admission rejected.","type":"admission_rejected","reason":"%s"}}`, reason,
		))
	}
	if len(public) != ed25519.PublicKeySize {
		t.Fatal("fixture public key has wrong size")
	}
	return fixtures
}

func stageCMustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func intPointer(value int) *int              { return &value }
func boolPointer(value bool) *bool           { return &value }
func int64PointerFixture(value int64) *int64 { return &value }
