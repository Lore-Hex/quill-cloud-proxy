package trustedrouter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAuthorizeBootAuthSignsExactWireBody(t *testing.T) {
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	var wireBody []byte
	var bootAuthHeader string
	countedValue := &countingJSONValue{}
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		wireBody, err = io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		bootAuthHeader = request.Header.Get(spendlease.BootAuthHeader)
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Request: request,
			Body: io.NopCloser(bytes.NewBufferString(`{"data":{"authorization_id":"auth-1","workspace_id":"ws-1"}}`)),
		}, nil
	})})
	client.ConfigureSpendLeaseShadow(signer, nil)
	if _, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{
		Model: "model-1", Metadata: map[string]any{"counted": countedValue},
	}); err != nil {
		t.Fatal(err)
	}
	if countedValue.calls != 1 {
		t.Fatalf("authorize body marshaled %d times, want exactly once", countedValue.calls)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(wireBody, &payload); err != nil {
		t.Fatal(err)
	}
	if _, exists := payload["boot_auth"]; exists {
		t.Fatalf("boot_auth must not be in authorize body: %s", wireBody)
	}
	var echo spendlease.Echo
	if err := json.Unmarshal(payload["spend_lease_echo"], &echo); err != nil || echo.State != "dormant" {
		t.Fatalf("shadow echo = %s, err = %v", payload["spend_lease_echo"], err)
	}
	kid, signature := parseBootAuthHeader(t, bootAuthHeader)
	if kid != signer.Kid() {
		t.Fatalf("boot auth kid = %q, want %q", kid, signer.Kid())
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(signer.JWK().X)
	if err != nil {
		t.Fatal(err)
	}
	digest := spendlease.AuthorizeDigest(http.MethodPost, spendlease.AuthorizePath, wireBody)
	if !ed25519.Verify(publicKey, digest[:], signature) {
		t.Fatal("X-TR-Boot-Auth signature does not cover the body bytes written to the transport")
	}
}

func TestAuthorizeRetriesReuseIdenticalBodyAndBootAuthHeader(t *testing.T) {
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	var bodies [][]byte
	var bootAuthHeaders []string
	attempts := 0
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		bodies = append(bodies, body)
		bootAuthHeaders = append(bootAuthHeaders, request.Header.Get(spendlease.BootAuthHeader))
		attempts++
		status := http.StatusServiceUnavailable
		responseBody := `{"error":{"type":"service_unavailable"}}`
		if attempts == 2 {
			status = http.StatusOK
			responseBody = `{"data":{"authorization_id":"auth-1","workspace_id":"ws-1"}}`
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(responseBody)), Request: request}, nil
	})})
	client.authorizeRetry = retryPolicy{attempts: 2, sleep: func(_ context.Context, _ time.Duration) error { return nil }}
	client.ConfigureSpendLeaseShadow(signer, nil)
	if _, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{Model: "model-1"}); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("retry bodies differ:\n%s\n%s", bodyAt(bodies, 0), bodyAt(bodies, 1))
	}
	if len(bootAuthHeaders) != 2 || bootAuthHeaders[0] == "" || bootAuthHeaders[0] != bootAuthHeaders[1] {
		t.Fatalf("retry boot auth headers differ: %q", bootAuthHeaders)
	}
}

func TestAuthorizeDecodeSeamVerifiesInstallsAndEchoesResponseGrant(t *testing.T) {
	bootSigner, err := receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerDigest := sha256.Sum256(issuerPublic)
	issuerKID := base64.RawURLEncoding.EncodeToString(issuerDigest[:])
	now := time.Now()
	config, _ := json.Marshal(spendlease.IssuerConfig{Version: 1, Keys: []spendlease.IssuerKey{{
		KID:       issuerKID,
		JWK:       spendlease.JWK{KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(issuerPublic)},
		NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix(),
	}}})
	verifier, err := spendlease.NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	claims := spendlease.Claims{
		Version: 1, Type: spendlease.JWSType, LeaseID: "123e4567-e89b-42d3-a456-426614174000",
		KeyHash: lookupHash("sk-test"), WorkspaceID: "ws-1", Cohort: spendlease.Cohort,
		CapMicro: 3, Generation: 1, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		BootKID: bootSigner.Kid(), Catalog: spendlease.Catalog{Version: "catalog-1", Candidates: []spendlease.Candidate{{
			EndpointID: "endpoint-1", Model: "model-1", Provider: "provider-1", RouteType: "chat.completions", RequestPriceMicro: 3,
		}}},
	}
	headerJSON, _ := json.Marshal(map[string]any{
		"alg": "EdDSA", "typ": spendlease.JWSType, "kid": issuerKID,
		"jwk": spendlease.JWK{KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(issuerPublic)},
	})
	claimsJSON, _ := json.Marshal(claims)
	protected := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := protected + "." + payload
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerPrivate, []byte(signingInput)))

	var requestBodies [][]byte
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		requestBodies = append(requestBodies, body)
		responseData := map[string]any{"authorization_id": "auth", "workspace_id": "ws-1"}
		if len(requestBodies) == 1 {
			responseData["spend_lease"] = spendlease.Response{Token: &token, LeaseStatus: "active"}
		}
		responseBody, _ := json.Marshal(map[string]any{"data": responseData})
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: request, Body: io.NopCloser(bytes.NewReader(responseBody))}, nil
	})})
	client.ConfigureSpendLeaseShadow(bootSigner, verifier)
	client.spendLease.state.SetRegistered(true)
	for range 2 {
		if _, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{Model: "model-1"}); err != nil {
			t.Fatal(err)
		}
	}
	var second map[string]any
	if err := json.Unmarshal(requestBodies[1], &second); err != nil {
		t.Fatal(err)
	}
	echo := second["spend_lease_echo"].(map[string]any)
	if echo["lease_id"] != claims.LeaseID || echo["state"] != "active" || echo["remaining_micro"] != float64(3) || echo["would_admit"] != true {
		t.Fatalf("second authorize did not echo verified pre-request state: %#v", echo)
	}
}

func TestBootRegistrationRetriesIdenticalPayloadAndRequiresVerifiedResponse(t *testing.T) {
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerDigest := sha256.Sum256(issuerPublic)
	issuerKID := base64.RawURLEncoding.EncodeToString(issuerDigest[:])
	config, _ := json.Marshal(spendlease.IssuerConfig{Version: 1, Keys: []spendlease.IssuerKey{{
		KID:       issuerKID,
		JWK:       spendlease.JWK{KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(issuerPublic)},
		NotBefore: time.Now().Add(-time.Hour).Unix(), NotAfter: time.Now().Add(time.Hour).Unix(),
	}}})
	verifier, err := spendlease.NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	called := make(chan []byte, 2)
	attempts := 0
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != spendlease.RegisterPath {
			t.Fatalf("path = %q", request.URL.Path)
		}
		body, _ := io.ReadAll(request.Body)
		called <- body
		attempts++
		if attempts == 1 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Request: request,
				Body: io.NopCloser(bytes.NewBufferString(`{"error":{"type":"service_unavailable"}}`)),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Request: request,
			Body: io.NopCloser(bytes.NewBufferString(`{"data":{"verified":true}}`)),
		}, nil
	})})
	client.authorizeRetry = retryPolicy{attempts: 2, sleep: func(_ context.Context, _ time.Duration) error { return nil }}
	client.ConfigureSpendLeaseShadow(signer, verifier)
	client.StartSpendLeaseBootRegistration(t.Context(), signer, BootRegistrationEvidence{Attestation: "evidence", AttestationKind: "gcp-cs-jwt"})
	var registrationBodies [][]byte
	for len(registrationBodies) < 2 {
		select {
		case body := <-called:
			registrationBodies = append(registrationBodies, body)
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			if payload["kid"] != signer.Kid() || payload["attestation_evidence"] != "evidence" {
				t.Fatalf("registration payload = %#v", payload)
			}
		case <-time.After(time.Second):
			t.Fatal("registration retry was not posted")
		}
	}
	if !bytes.Equal(registrationBodies[0], registrationBodies[1]) {
		t.Fatalf("registration retry changed payload:\n%s\n%s", registrationBodies[0], registrationBodies[1])
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !client.spendLease.state.Registered() {
		time.Sleep(time.Millisecond)
	}
	if !client.spendLease.state.Registered() {
		t.Fatal("verified registration did not activate shadow state")
	}
}

func TestSpendLeaseFeatureOffLeavesAuthorizeWireShapeUnchanged(t *testing.T) {
	var bodies [][]byte
	var bootAuthHeaders []string
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		bodies = append(bodies, body)
		bootAuthHeaders = append(bootAuthHeaders, request.Header.Get(spendlease.BootAuthHeader))
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Request: request,
			Body: io.NopCloser(bytes.NewBufferString(`{"data":{"authorization_id":"auth-1"}}`)),
		}, nil
	})})
	if _, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{Model: "model-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AuthorizeEmbeddings(t.Context(), "sk-test", &qtypes.EmbeddingRequest{Model: "embedding-1"}, 2); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 {
		t.Fatalf("authorize bodies = %d, want chat + embeddings", len(bodies))
	}
	for index, body := range bodies {
		if bootAuthHeaders[index] != "" {
			t.Fatalf("flag-off authorize unexpectedly contains boot auth header %q", bootAuthHeaders[index])
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"boot_auth", "spend_lease_echo"} {
			if _, exists := payload[forbidden]; exists {
				t.Fatalf("flag-off authorize unexpectedly contains %q: %s", forbidden, body)
			}
		}
	}
}

func TestSpendLeaseProviderConstraintExtraction(t *testing.T) {
	noFallbacks := false
	withFallbacks := true
	for _, test := range []struct {
		name    string
		routing *qtypes.ProviderRouting
		want    []string
	}{
		{name: "only is exact", routing: &qtypes.ProviderRouting{Only: qtypes.StringList{"p1", "p2"}}, want: []string{"p1", "p2"}},
		{name: "ordered set exact when fallbacks disabled", routing: &qtypes.ProviderRouting{Order: qtypes.StringList{"p1", "p2"}, AllowFallbacks: &noFallbacks}, want: []string{"p1", "p2"}},
		{name: "order is preference when fallbacks enabled", routing: &qtypes.ProviderRouting{Order: qtypes.StringList{"p1"}, AllowFallbacks: &withFallbacks}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := spendLeaseRequestForChat("us", "chat.completions", &qtypes.OpenAIChatRequest{Model: "m", Provider: test.routing}).ProviderConstraints
			if strings.Join(got, ",") != strings.Join(test.want, ",") {
				t.Fatalf("constraints = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAuthorizePostsPassThroughSpendLeaseDecodeSeam(t *testing.T) {
	clientSource, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatal(err)
	}
	seamSource, err := os.ReadFile("spend_lease.go")
	if err != nil {
		t.Fatal(err)
	}
	bypass := regexp.MustCompile(`(?s)postJSONWithRetryAtEndpoint\([^)]*"/internal/gateway/authorize"`)
	if bypass.Match(clientSource) {
		t.Fatal("client.go contains an authorize POST that bypasses the spend-lease seam")
	}
	if got := strings.Count(string(clientSource), "authorizeAtDecodeSeam("); got != 2 {
		t.Fatalf("authorize entry points using decode seam = %d, want chat + embeddings", got)
	}
	if !strings.Contains(string(seamSource), "postJSONBytesWithRetryAtEndpoint(") || !strings.Contains(string(seamSource), "HandleResponse(") {
		t.Fatal("decode seam no longer owns both authorize POST and lease verification")
	}
}

func bodyAt(bodies [][]byte, index int) []byte {
	if index < 0 || index >= len(bodies) {
		return nil
	}
	return bodies[index]
}

func parseBootAuthHeader(t *testing.T, value string) (string, []byte) {
	t.Helper()
	kidPart, sigPart, ok := strings.Cut(value, ",")
	if !ok || !strings.HasPrefix(kidPart, "kid=") || !strings.HasPrefix(sigPart, "sig=") {
		t.Fatalf("X-TR-Boot-Auth = %q", value)
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sigPart, "sig="))
	if err != nil {
		t.Fatalf("decode X-TR-Boot-Auth signature: %v", err)
	}
	return strings.TrimPrefix(kidPart, "kid="), signature
}

type countingJSONValue struct {
	calls int
}

func (value *countingJSONValue) MarshalJSON() ([]byte, error) {
	value.calls++
	return []byte(`"counted"`), nil
}

// Stage A must compare raw tiers and emit the same advisory echo while local
// admission is disabled, even when router normalization would match a catalog.
func TestSpendLeaseLocalAdmissionOffPreservesRawTierEcho(t *testing.T) {
	for _, route := range []string{"chat.completions", "responses"} {
		t.Run(route, func(t *testing.T) {
			signer := stageCFixtureSigner(t)
			now := time.UnixMilli(2_000_000_005_000)
			var claims spendlease.Claims
			if err := json.Unmarshal(stageCFixture(t, "authoritative_lease_payload.json"), &claims); err != nil {
				t.Fatal(err)
			}
			claims.Authoritative, claims.LocalAdmissionAllowed = false, false
			claims.KeyHash = stageCFixtureLookupHash
			claims.RoutingPolicyHash = ""
			for i := range claims.Catalog.Candidates {
				claims.Catalog.Candidates[i].ServiceTier = "default"
				claims.Catalog.Candidates[i].RouteType = route
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
			header, err := json.Marshal(map[string]string{"alg": "EdDSA", "kid": signer.Kid(), "typ": spendlease.JWSType})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			token := stageCSignCompactInputs(t, signer, header, payload)
			var bodies []map[string]json.RawMessage
			client := New("https://trustedrouter.com", "internal", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
				data := map[string]any{"authorization_id": "ordinary", "workspace_id": claims.WorkspaceID}
				if len(bodies) == 1 {
					data["spend_lease"] = spendlease.Response{Token: &token, LeaseStatus: "active"}
				}
				raw, err := json.Marshal(map[string]any{"data": data})
				if err != nil {
					t.Fatal(err)
				}
				return replayResponse(r, raw), nil
			})})
			client.region = "us-central1"
			client.ConfigureSpendLeaseShadow(signer, verifier)
			client.ConfigureSpendLeaseLocalAdmission(false)
			client.spendLease.state.SetRegistered(true)
			client.spendLease.now = func() time.Time { return now }
			req := stageCFixtureRequest()
			req.ServiceTier = "default"
			if _, err := client.AuthorizeWithRoute(fixedStageCContext(), "sk-stage-c-fixture", req, route); err != nil {
				t.Fatal(err)
			}
			before := stageCCapacity(t, client)
			if before != claims.CapMicro {
				t.Fatalf("cold grant capacity = %d, want %d", before, claims.CapMicro)
			}
			req.ServiceTier = " DeFaUlT "
			if _, err := client.AuthorizeWithRoute(fixedStageCContext(), "sk-stage-c-fixture", req, route); err != nil {
				t.Fatal(err)
			}
			// This literal is the pre-PR Stage A wire echo, including null estimate.
			wantEcho := `{"lease_id":"00000000-0000-4000-8000-000000000067","state":"no-applicable-lease","remaining_micro":1000000,"enclave_estimate_micro":null,"catalog_version":"spend-lease-catalog-v1:cb46fe1ece15e430ef5411a40d4326d402f8d89460c3ad611bed2219859a0f89","would_admit":false}`
			if got := string(bodies[1]["spend_lease_echo"]); got != wantEcho {
				t.Errorf("flag-off echo = %s, want %s", got, wantEcho)
			}
			if got := string(bodies[1]["service_tier"]); got != `" DeFaUlT "` {
				t.Errorf("flag-off raw tier changed: %s", got)
			}
			if after := stageCCapacity(t, client); after != before {
				t.Errorf("flag-off unmatched tier spent shadow capacity: before=%d after=%d", before, after)
			}
			// A byte-exact match still spends shadow capacity, proving the grant is
			// usable and the negative case did not merely bypass Stage A entirely.
			req.ServiceTier = "default"
			if _, err := client.AuthorizeWithRoute(fixedStageCContext(), "sk-stage-c-fixture", req, route); err != nil {
				t.Fatal(err)
			}
			var matched spendlease.Echo
			if err := json.Unmarshal(bodies[2]["spend_lease_echo"], &matched); err != nil {
				t.Fatal(err)
			}
			if matched.State != "active" || matched.WouldAdmit == nil || !*matched.WouldAdmit || matched.EnclaveEstimateMicro == nil {
				t.Fatalf("exact default did not match Stage A catalog: %+v", matched)
			}
			if after := stageCCapacity(t, client); after != before-*matched.EnclaveEstimateMicro {
				t.Fatalf("exact default capacity = %d, want %d", after, before-*matched.EnclaveEstimateMicro)
			}
		})
	}
}
