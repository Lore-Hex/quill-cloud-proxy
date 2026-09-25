package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
	stageCMarkerlessBearer      = "sk-stage-c-markerless" //nolint:gosec // deterministic public test fixture, not a credential
	stageCMarkerlessModel       = "openai/gpt-4o-mini"
	stageCLocalEndpoint         = "openai/gpt-4o-mini@local-snapshot/prepaid"
	stageCReservedEndpoint      = "openai/gpt-4o-mini@reserved-router/prepaid"
	stageCMarkerlessWorkspaceID = "ws_stage_c_markerless"
	stageCStoredKeyID           = "stored-stage-c-key-id"
	stageCMarkerlessRequestBody = `{"model":"openai/gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"markerless"}],"max_tokens":64,"provider":{"only":["local-snapshot"],"usage":"credits","allow_fallbacks":false,"data_collection":"deny"}}`
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
				reserve, err := stageCMarkerlessReserveBody(body)
				if err != nil {
					return nil, err
				}
				if !reserve {
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
	stageCPrimeLeaseForRoute(t, gateway, "chat.completions")
}

func stageCPrimeLeaseForRoute(t *testing.T, gateway *trustedrouter.Client, route string) {
	t.Helper()
	stageCPrimeLeaseForRouteAndTier(t, gateway, route, "", false)
}

func stageCPrimeLeaseForRouteAndTier(t *testing.T, gateway *trustedrouter.Client, route, tier string, tierPresent bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		prime := stageCMarkerlessRequest(t, fmt.Sprintf("markerless-prime-%d", attempt))
		prime.ServiceTier = tier
		if tierPresent && route == "chat.completions" {
			prime.RequestedParameters = append(prime.RequestedParameters, "service_tier")
		}
		ctx := trustedrouter.WithAuthorizationInvocation(context.Background())
		if _, err := gateway.AuthorizeWithRoute(ctx, stageCMarkerlessBearer, prime, route); err != nil {
			t.Fatalf("prime spend lease: %v", err)
		}
		probe := stageCMarkerlessRequest(t, fmt.Sprintf("markerless-probe-%d", attempt))
		probe.ServiceTier = tier
		if tierPresent && route == "chat.completions" {
			probe.RequestedParameters = append(probe.RequestedParameters, "service_tier")
		}
		plan, err := gateway.PrepareSpendLeaseAdmission(trustedrouter.WithAuthorizationInvocation(context.Background()), stageCMarkerlessBearer, probe, route, time.Now())
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
	return stageCLeaseForRoute(t, "chat.completions")
}

func stageCLeaseForRoute(t *testing.T, route string) (string, *receipt.Signer, *spendlease.Verifier) {
	t.Helper()
	return stageCLeaseForRouteAndTier(t, route, "", false)
}

func stageCLeaseForRouteAndTier(t *testing.T, route, tier string, tierPresent bool) (string, *receipt.Signer, *spendlease.Verifier) {
	t.Helper()
	req := stageCMarkerlessRequest(t, "lease-policy")
	req.ServiceTier = tier
	if tierPresent && route == "chat.completions" {
		req.RequestedParameters = append(req.RequestedParameters, "service_tier")
	}
	policyHash, eligible := trustedrouter.RoutingPolicyHash(req, route, "")
	if !eligible {
		t.Fatal("fixture route ineligible")
	}
	signer, err := receipt.NewSignerFromSeed(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := spendlease.Claims{
		Version: 1, Type: spendlease.JWSType, Authoritative: true, LocalAdmissionAllowed: true,
		RoutingPolicyHash: policyHash, LeaseID: "123e4567-e89b-42d3-a456-426614174099",
		KeyHash: stageCStoredKeyID, WorkspaceID: stageCMarkerlessWorkspaceID,
		Cohort: spendlease.Cohort, CapMicro: 10000, Generation: 1,
		IssuedAt: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(59 * time.Second).Unix(), BootKID: signer.Kid(),
		Catalog: spendlease.Catalog{Version: "stage-c-markerless", Candidates: []spendlease.Candidate{{
			EndpointID: stageCLocalEndpoint, Model: stageCMarkerlessModel, UpstreamModel: "gpt-4o-mini",
			Provider: "local-snapshot", UsageType: "Credits", Region: "", RouteType: route, ServiceTier: tier,
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
	hash, eligible := trustedrouter.RoutingPolicyHash(
		stageCMarkerlessRequest(t, "markerless-lease-policy"),
		"chat.completions",
		"",
	)
	if !eligible {
		t.Fatal("markerless lease request is not eligible for Stage-C routing normalization")
	}
	return hash
}

func stageCMarkerlessReserveBody(body map[string]any) (bool, error) {
	receipt, reserve := body["spend_lease_admission"]
	if !reserve {
		return false, nil
	}
	if receipt, ok := receipt.(string); !ok || receipt == "" {
		return false, fmt.Errorf("canonical reserve body has invalid spend_lease_admission: %#v", receipt)
	}
	wantProvider := map[string]any{
		"allow_fallbacks": false,
		"data_collection": "deny",
		"only":            []any{"local-snapshot"},
		"usage":           "credits",
	}
	wantRequestedParameters := []any{"max_tokens"}
	if body["api_key_lookup_hash"] != trustedrouter.LookupHash(stageCMarkerlessBearer) ||
		body["model"] != stageCMarkerlessModel || body["route_type"] != "chat.completions" ||
		body["stream"] != true || body["region"] != "" || body["max_tokens"] != float64(64) ||
		!reflect.DeepEqual(body["provider"], wantProvider) ||
		!reflect.DeepEqual(body["requested_parameters"], wantRequestedParameters) {
		return false, fmt.Errorf("unexpected canonical reserve body: %#v", body)
	}
	for _, ordinaryOnly := range []string{"api_key_hash", "invocation_nonce", "max_output_tokens", "spend_lease_echo"} {
		if _, present := body[ordinaryOnly]; present {
			return false, fmt.Errorf("canonical reserve body retained %q: %#v", ordinaryOnly, body)
		}
	}
	return true, nil
}

func stageCMarkerlessAuthorization(authorizationID, endpointID, provider string) map[string]any {
	return map[string]any{
		"request_metadata_version": 1, "authorization_id": authorizationID, "workspace_id": stageCMarkerlessWorkspaceID,
		"api_key_hash": stageCStoredKeyID, "model": stageCMarkerlessModel,
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

type stageCLostAckReadBody struct{}

func (stageCLostAckReadBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (stageCLostAckReadBody) Close() error             { return nil }

func TestServeOneStageCLostAckReplayExecutesAndFinalizesOnce(t *testing.T) {
	for _, boundary := range []string{"before_headers", "body_read_reset"} {
		t.Run(boundary, func(t *testing.T) {
			provider := &replayCountingProvider{}
			token, signer, verifier := stageCMarkerlessLease(t)
			prime := stageCMarkerlessAuthorization("prime", stageCLocalEndpoint, "local-snapshot")
			prime["spend_lease"] = map[string]any{"token": token, "lease_status": "active"}
			var attempts, allocations, finalizations atomic.Int32
			var originalBody []byte
			var originalProof string
			var stored map[string]any
			gateway := trustedrouter.New("https://trustedrouter.com", "internal-token", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case spendlease.RegisterPath:
					return replayHTTPResponse(r, 200, `{"data":{"verified":true}}`), nil
				case spendlease.AuthorizePath:
					raw, err := io.ReadAll(r.Body)
					if err != nil {
						return nil, err
					}
					var body map[string]any
					if err := json.Unmarshal(raw, &body); err != nil {
						return nil, err
					}
					receipt, ok := body["spend_lease_admission"].(string)
					if !ok {
						return stageCMarkerlessHTTPResponse(r, map[string]any{"data": prime})
					}
					if body["invocation_nonce"] != nil {
						t.Error("Stage C sent an ordinary nonce")
					}
					if attempts.Add(1) == 1 {
						allocations.Add(1)
						originalBody = append([]byte(nil), raw...)
						originalProof = r.Header.Get(spendlease.BootAuthHeader)
						stored = stageCMarkerlessAuthorization("original-committed", stageCLocalEndpoint, "local-snapshot")
						stored["requested_model"] = stageCMarkerlessModel
						stored["route_candidates"] = []any{map[string]any{"endpoint_id": stageCLocalEndpoint, "model": stageCMarkerlessModel, "upstream_model": "gpt-4o-mini", "provider": "local-snapshot", "usage_type": "Credits"}}
						stored["spend_lease_admission"] = map[string]any{"accepted": true, "receipt_hash": spendlease.AdmissionReceiptHash(receipt)}
						stored["spend_lease"] = map[string]any{"token": token, "lease_status": "active", "remaining_micro": 9900}
						stored["invocation_nonce"] = body["invocation_nonce"] // original absent nonce, as the router stores it
						if boundary == "body_read_reset" {
							response := replayHTTPResponse(r, 200, "")
							response.Body = stageCLostAckReadBody{}
							return response, nil
						}
						return nil, io.ErrUnexpectedEOF
					}
					if !bytes.Equal(raw, originalBody) || originalProof == "" || r.Header.Get(spendlease.BootAuthHeader) != originalProof {
						t.Error("reserve retry changed body/proof")
					}
					stored["idempotent_replay"] = true
					stored["stage_d"] = map[string]any{"eligible": false, "reason": "replayed"}
					return stageCMarkerlessHTTPResponse(r, map[string]any{"data": stored})
				case "/internal/gateway/settle":
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						return nil, err
					}
					if body["authorization_id"] != "original-committed" {
						t.Errorf("wrong finalization: %v", body["authorization_id"])
					}
					finalizations.Add(1)
					return replayHTTPResponse(r, 200, `{"data":{"settled":true,"generation_id":"gen-lost-ack","cost_microdollars":1,"model":"openai/gpt-4o-mini","provider":"local-snapshot"}}`), nil
				default:
					t.Errorf("unexpected router operation: %s", r.URL.Path)
					return replayHTTPResponse(r, 404, `{}`), nil
				}
			})})
			gateway.ConfigureSpendLeaseShadow(signer, verifier)
			gateway.ConfigureSpendLeaseLocalAdmission(true)
			gateway.StartSpendLeaseBootRegistration(context.Background(), signer, trustedrouter.BootRegistrationEvidence{Attestation: "test", AttestationKind: "test"})
			stageCPrimeMarkerlessLease(t, gateway)
			raw := fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer %s\r\nIdempotency-Key: lost-ack-public\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", stageCMarkerlessBearer, len(stageCMarkerlessRequestBody), stageCMarkerlessRequestBody)
			conn := newScriptedConn(raw, nil)
			serveOne(context.Background(), conn, auth.New(nil), provider, nil, nil, gateway, nil)
			response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(conn.writes.Bytes())), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 || !bytes.Contains(body, []byte(`"content":"ok"`)) {
				t.Fatalf("status=%d body=%s", response.StatusCode, body)
			}
			if attempts.Load() != 2 || allocations.Load() != 1 || provider.dispatches.Load() != 1 || finalizations.Load() != 1 {
				t.Fatalf("attempt/allocation/provider/finalize=%d/%d/%d/%d", attempts.Load(), allocations.Load(), provider.dispatches.Load(), finalizations.Load())
			}
		})
	}
}

// Non-streaming Chat and Responses still use InvokeStreaming internally. The
// public bit must reach ordinary authorization before that provider starts.
func TestServeOneStageCLocalMissMatrixAuthorizesBeforeProvider(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		value any
	}{
		{"non_streaming", "stream", false},
		{"whitespace_only", "service_tier", " \t\n"},
		{"padded_default", "service_tier", " default "},
		{"uppercase_default", "service_tier", "DEFAULT"},
		{"mixed_case_default", "service_tier", " DeFaUlT "},
		{"overlength_default", "service_tier", strings.Repeat(" ", 21) + "default"},
		{"priority", "service_tier", "priority"},
		{"auto", "service_tier", "auto"},
		{"priority_normalized", "service_tier", " PrIoRiTy "},
		{"auto_normalized", "service_tier", " AUTO "},
		{"unknown_tier", "service_tier", "flex"},
		{"max_price", "max_price", map[string]any{"prompt": 1}},
		{"jurisdiction", "jurisdiction", "US"},
		{"usage_type_only", "usage_type", "credits"},
		{"billing_only", "billing", "credits"},
		{"tags", "tags", map[string]any{}},
	} {
		for _, route := range []string{"chat.completions", "responses"} {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				provider := &replayCountingProvider{}
				// Acquire a matching canonical grant before submitting the raw tier.
				grantTier := ""
				if tc.field == "service_tier" {
					grantTier = strings.ToLower(strings.TrimSpace(tc.value.(string)))
				}
				// Priority/auto/unknown cases retain the ordinary baseline grant.
				if grantTier != "default" {
					grantTier = ""
				}
				token, signer, verifier := stageCLeaseForRouteAndTier(t, route, grantTier, tc.field == "service_tier")
				prime := stageCMarkerlessAuthorization("prime", stageCLocalEndpoint, "local-snapshot")
				prime["spend_lease"] = map[string]any{"token": token, "lease_status": "active"}
				var ready atomic.Bool
				var authorizes, settles atomic.Int32
				gateway := trustedrouter.New("https://trustedrouter.com", "internal-token", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					switch r.URL.Path {
					case spendlease.RegisterPath:
						return replayHTTPResponse(r, 200, `{"data":{"verified":true}}`), nil
					case spendlease.AuthorizePath:
						var body map[string]any
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							return nil, err
						}
						if !ready.Load() {
							return stageCMarkerlessHTTPResponse(r, map[string]any{"data": prime})
						}
						authorizes.Add(1)
						if body["stream"] != (tc.name != "non_streaming") || body["route_type"] != route || body["spend_lease_admission"] != nil || body["invocation_nonce"] == nil {
							t.Errorf("non-streaming public request attempted admission or lost stream/nonce: %v", body)
						}
						if tc.field == "service_tier" && body["service_tier"] != tc.value {
							t.Errorf("ordinary authorization changed raw tier: %v", body["service_tier"])
						}
						if provider.dispatches.Load() != 0 {
							t.Error("provider speculation started before ordinary authorization")
						}
						return stageCMarkerlessHTTPResponse(r, map[string]any{"data": stageCMarkerlessAuthorization("ordinary", stageCLocalEndpoint, "local-snapshot")})
					case "/internal/gateway/settle":
						settles.Add(1)
						return replayHTTPResponse(r, 200, `{"data":{"settled":true}}`), nil
					default:
						t.Errorf("unexpected operation: %s", r.URL.Path)
						return replayHTTPResponse(r, 404, `{}`), nil
					}
				})})
				gateway.ConfigureSpendLeaseShadow(signer, verifier)
				gateway.ConfigureSpendLeaseLocalAdmission(true)
				gateway.StartSpendLeaseBootRegistration(context.Background(), signer, trustedrouter.BootRegistrationEvidence{Attestation: "test", AttestationKind: "test"})
				stageCPrimeLeaseForRouteAndTier(t, gateway, route, grantTier, tc.field == "service_tier")
				ready.Store(true)
				body := stageCMarkerlessRequestBody
				path := "/v1/chat/completions"
				if route == "responses" {
					path = "/v1/responses"
					body = `{"model":"openai/gpt-4o-mini","stream":true,"input":"markerless","max_output_tokens":64,"provider":{"only":["local-snapshot"],"usage":"credits","allow_fallbacks":false,"data_collection":"deny"}}`
				}
				var public map[string]any
				if err := json.Unmarshal([]byte(body), &public); err != nil {
					t.Fatal(err)
				}
				switch tc.field {
				case "max_price", "jurisdiction", "usage_type", "billing":
					p := public["provider"].(map[string]any)
					p[tc.field] = tc.value
					if tc.field == "usage_type" || tc.field == "billing" {
						delete(p, "usage")
					}
				default:
					public[tc.field] = tc.value
				}
				encoded, err := json.Marshal(public)
				if err != nil {
					t.Fatal(err)
				}
				body = string(encoded)
				raw := fmt.Sprintf("POST %s HTTP/1.1\r\nAuthorization: Bearer %s\r\nIdempotency-Key: non-streaming-public\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", path, stageCMarkerlessBearer, len(body), body)
				conn := newScriptedConn(raw, nil)
				serveOne(context.Background(), conn, auth.New(nil), provider, nil, nil, gateway, nil)
				response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(conn.writes.Bytes())), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				publicBody, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != 200 || !bytes.Contains(publicBody, []byte(`"ok"`)) {
					t.Fatalf("non-streaming response: status=%d body=%s", response.StatusCode, publicBody)
				}
				if authorizes.Load() != 1 || provider.dispatches.Load() != 1 || settles.Load() != 1 {
					t.Fatalf("ordinary/provider/finalize=%d/%d/%d", authorizes.Load(), provider.dispatches.Load(), settles.Load())
				}
			})
		}
	}

}
