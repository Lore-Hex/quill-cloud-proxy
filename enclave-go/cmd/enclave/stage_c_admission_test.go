package main

import (
	"bufio"
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
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	stageCMarkerlessBearer      = "sk-stage-c-markerless"
	stageCMarkerlessModel       = "openai/gpt-4o-mini"
	stageCLocalEndpoint         = "openai/gpt-4o-mini@local-snapshot/prepaid"
	stageCReservedEndpoint      = "openai/gpt-4o-mini@reserved-router/prepaid"
	stageCMarkerlessWorkspaceID = "ws_stage_c_markerless"
	stageCMarkerlessRequestBody = `{"model":"openai/gpt-4o-mini","stream":false,"messages":[{"role":"user","content":"markerless"}],"max_tokens":64,"provider":{"only":["local-snapshot"],"usage":"credits","allow_fallbacks":false,"data_collection":"deny","zdr":true}}`
)

type stageCMarkerlessLeaseHeader struct {
	Algorithm string      `json:"alg"`
	Type      string      `json:"typ"`
	KID       string      `json:"kid"`
	JWK       receipt.JWK `json:"jwk"`
}

func TestServeOneStageCUnmarkedReserveCancelsBeforeRedispatch(t *testing.T) {
	provider := &stageCCancelClient{
		started:             make(chan struct{}),
		done:                make(chan struct{}),
		speculativeResponse: strings.Replace(providerStreamTestResponse, `"text":"ok"`, `"text":"SPECULATIVE-MUST-NOT-RELAY"`, 1),
		redispatchResponse:  providerStreamTestResponse,
	}
	leaseToken, signer, verifier := stageCMarkerlessLease(t)
	leaseResponse := stageCMarkerlessAuthorization("prime-authorization", stageCLocalEndpoint, "local-snapshot")
	leaseResponse["spend_lease"] = map[string]any{"token": leaseToken, "lease_status": "active"}
	unmarkedResponse := stageCMarkerlessAuthorization("reserved-authorization", stageCReservedEndpoint, "reserved-router")

	var registerOnce sync.Once
	registerSeen := make(chan struct{})
	var reserveCalls atomic.Int32
	var settleCalls atomic.Int32
	var settledAuthorization atomic.Value
	gateway := trustedrouter.New("https://trustedrouter.com", "internal-token", &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			switch request.URL.Path {
			case spendlease.RegisterPath:
				registerOnce.Do(func() { close(registerSeen) })
				return replayHTTPResponse(request, http.StatusOK, `{"data":{"verified":true}}`), nil
			case spendlease.AuthorizePath:
				var body map[string]any
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					return nil, err
				}
				if body["spend_lease_admission"] == nil {
					return stageCMarkerlessHTTPResponse(request, map[string]any{"data": leaseResponse})
				}
				reserveCalls.Add(1)
				select {
				case <-provider.started:
				case <-request.Context().Done():
					return nil, request.Context().Err()
				}
				return stageCMarkerlessHTTPResponse(request, map[string]any{"data": unmarkedResponse})
			case "/internal/gateway/settle":
				var body map[string]any
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					return nil, err
				}
				settledAuthorization.Store(body["authorization_id"])
				settleCalls.Add(1)
				return replayHTTPResponse(request, http.StatusOK, `{"data":{"settled":true,"generation_id":"gen-markerless","cost_microdollars":1,"model":"openai/gpt-4o-mini","provider":"reserved-router","region":"test"}}`), nil
			default:
				return replayHTTPResponse(request, http.StatusNotFound, `{"error":{"message":"not found"}}`), nil
			}
		}),
	})
	gateway.ConfigureSpendLeaseShadow(signer, verifier)
	gateway.ConfigureSpendLeaseLocalAdmission(true)
	gateway.StartSpendLeaseBootRegistration(context.Background(), signer, trustedrouter.BootRegistrationEvidence{
		Attestation: "test-attestation", AttestationKind: "test",
	})
	select {
	case <-registerSeen:
	case <-time.After(time.Second):
		t.Fatal("spend-lease boot registration was not attempted")
	}
	stageCPrimeMarkerlessLease(t, gateway)

	rawRequest := fmt.Sprintf(
		"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nIdempotency-Key: markerless-public-request\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		stageCMarkerlessBearer, len(stageCMarkerlessRequestBody), stageCMarkerlessRequestBody,
	)
	conn := newScriptedConn(rawRequest, nil)
	serveOne(context.Background(), conn, auth.New(nil), provider, nil, nil, gateway, nil)

	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(conn.writes.Bytes())), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if response.StatusCode != http.StatusOK || !bytes.Contains(responseBody, []byte(`"content":"ok"`)) {
		t.Fatalf("status=%d body=%s, want re-dispatched response", response.StatusCode, responseBody)
	}
	if bytes.Contains(responseBody, []byte("SPECULATIVE-MUST-NOT-RELAY")) {
		t.Fatalf("speculative provider bytes reached the client: %s", responseBody)
	}
	select {
	case <-provider.done:
	case <-time.After(time.Second):
		t.Fatal("unmarked reserve did not cancel the speculative provider context")
	}
	endpoints, speculativeWriteBytes := provider.snapshot()
	if speculativeWriteBytes != 0 {
		t.Fatalf("speculative provider relayed %d bytes before cancellation", speculativeWriteBytes)
	}
	if want := []string{stageCLocalEndpoint, stageCReservedEndpoint}; !reflect.DeepEqual(endpoints, want) {
		t.Fatalf("provider dispatch endpoints = %q, want %q", endpoints, want)
	}
	if reserveCalls.Load() != 1 || settleCalls.Load() != 1 {
		t.Fatalf("reserve/settle calls = %d/%d, want 1/1", reserveCalls.Load(), settleCalls.Load())
	}
	if got, _ := settledAuthorization.Load().(string); got != "reserved-authorization" {
		t.Fatalf("settled authorization = %q, want reserved authorization", got)
	}
}

func stageCPrimeMarkerlessLease(t *testing.T, gateway *trustedrouter.Client) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		prime := stageCMarkerlessRequest(t, fmt.Sprintf("markerless-prime-%d", attempt))
		ctx := trustedrouter.WithAuthorizationInvocation(context.Background())
		if _, err := gateway.AuthorizeWithRoute(ctx, stageCMarkerlessBearer, prime, "chat.completions"); err != nil {
			t.Fatalf("prime spend lease: %v", err)
		}
		probe := stageCMarkerlessRequest(t, fmt.Sprintf("markerless-probe-%d", attempt))
		plan, err := gateway.PrepareSpendLeaseAdmission(context.Background(), stageCMarkerlessBearer, probe, "chat.completions", time.Now())
		if err != nil {
			t.Fatalf("probe local admission: %v", err)
		}
		if plan != nil {
			plan.Cancel()
			return
		}
		runtime.Gosched()
	}
	t.Fatal("spend lease did not become eligible for local admission")
}

func stageCMarkerlessRequest(t *testing.T, idempotencyKey string) *types.OpenAIChatRequest {
	t.Helper()
	req, err := parseChatRequest([]byte(stageCMarkerlessRequestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.NormalizeMaxTokens()
	if err := req.NormalizeFallbackRouting(); err != nil {
		t.Fatal(err)
	}
	req.IdempotencyKey = idempotencyKey
	return req
}

func stageCMarkerlessLease(t *testing.T) (string, *receipt.Signer, *spendlease.Verifier) {
	t.Helper()
	signer, err := receipt.NewSignerFromSeed(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := spendlease.Claims{
		Version: 1, Type: spendlease.JWSType, Authoritative: true, LocalAdmissionAllowed: true,
		RoutingPolicyHash: stageCMarkerlessPolicyHash(t), LeaseID: "123e4567-e89b-42d3-a456-426614174099",
		KeyHash: trustedrouter.LookupHash(stageCMarkerlessBearer), WorkspaceID: stageCMarkerlessWorkspaceID,
		Cohort: spendlease.Cohort, CapMicro: 10000, Generation: 1,
		IssuedAt: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(59 * time.Second).Unix(), BootKID: signer.Kid(),
		Catalog: spendlease.Catalog{Version: "stage-c-markerless", Candidates: []spendlease.Candidate{{
			EndpointID: stageCLocalEndpoint, Model: stageCMarkerlessModel, UpstreamModel: "gpt-4o-mini",
			Provider: "local-snapshot", UsageType: "Credits", Region: "", RouteType: "chat.completions",
			InputPriceMicroPerMTok: 150000, OutputPriceMicroPerMTok: 600000, CacheReadMicroPerMTok: 75000,
		}}},
	}
	headerJSON, err := json.Marshal(stageCMarkerlessLeaseHeader{
		Algorithm: "EdDSA", Type: spendlease.JWSType, KID: signer.Kid(), JWK: signer.JWK(),
	})
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	protected := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := protected + "." + payload
	signature, err := signer.SignMessage([]byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
	configJSON, err := json.Marshal(spendlease.IssuerConfig{Version: 1, Keys: []spendlease.IssuerKey{{
		KID: signer.Kid(), JWK: spendlease.JWK{KeyType: "OKP", Curve: "Ed25519", X: signer.JWK().X},
		NotBefore: claims.IssuedAt - 1, NotAfter: claims.IssuedAt + 1,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := spendlease.NewVerifier(configJSON)
	if err != nil {
		t.Fatal(err)
	}
	return token, signer, verifier
}

func stageCMarkerlessPolicyHash(t *testing.T) string {
	t.Helper()
	canonical := map[string]any{
		"allow_fallbacks": false, "country": "", "data_collection": "deny", "headquarters_country": "",
		"ignore": []string{}, "jurisdiction": "", "max_price": map[string]any{}, "min_privacy": "",
		"model": stageCMarkerlessModel, "only": []string{"local-snapshot"}, "order": []string{},
		"priority_eligible": true, "provider_country": "", "region": "", "requested_parameters": []string{"max_tokens"},
		"require_parameters": nil, "route_type": "chat.completions", "service_tier": "", "usage_type": "credits", "zdr": true,
	}
	body, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func stageCMarkerlessAuthorization(authorizationID, endpointID, provider string) map[string]any {
	return map[string]any{
		"authorization_id": authorizationID, "workspace_id": stageCMarkerlessWorkspaceID,
		"api_key_hash": trustedrouter.LookupHash(stageCMarkerlessBearer), "model": stageCMarkerlessModel,
		"upstream_model": "gpt-4o-mini", "endpoint_id": endpointID, "provider": provider,
		"usage_type": "Credits", "limit_usage_type": "Credits", "route_candidates": []any{},
	}
}

func stageCMarkerlessHTTPResponse(request *http.Request, value any) (*http.Response, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return replayHTTPResponse(request, http.StatusOK, string(body)), nil
}
