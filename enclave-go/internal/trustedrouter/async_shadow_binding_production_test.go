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
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Byte-identical to the router fixture; produced by real HTTP authorize,
// cohort authorize and ShadowSigner with the public deterministic test seed.
const productionBindingFixtureSHA = "d9dd89600421ac68da087f02dac99288241307f5804d24210006ca99cf163fb0"

func TestRouterProductionBindingShapes(t *testing.T) {
	raw, err := os.ReadFile("testdata/async_settlement/shadow_binding_production.json")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != productionBindingFixtureSHA {
		t.Fatal("fixture byte pin")
	}
	var fixture struct {
		Seed  string `json:"test_seed_hex"`
		Cases []struct {
			Name          string            `json:"name"`
			Binding       string            `json:"binding"`
			Claims        asyncTicketClaims `json:"claims"`
			Authorization json.RawMessage   `json:"authorization"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 8 {
		t.Fatal("eight probe shapes required")
	}
	seed, err := hex.DecodeString(fixture.Seed)
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	previous := enclaveOptedAdmission.Load()
	enclaveOptedAdmission.Store(nil)
	t.Cleanup(func() { enclaveOptedAdmission.Store(previous) })
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			claims, ok := shadowClaims(tc.Binding)
			if !ok {
				t.Fatal("shadowClaims rejected router-produced binding")
			}
			if claims != tc.Claims {
				t.Fatalf("claims differ: %+v", claims)
			}
			var authorization Authorization
			if err := json.Unmarshal(tc.Authorization, &authorization); err != nil {
				t.Fatal(err)
			}
			if string(authorization.BillingShadowBinding) != tc.Binding {
				t.Fatal("authorize decode changed proof")
			}
			parts := strings.Split(tc.Binding, ".")
			signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
			if err != nil || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
				t.Fatal("test signature")
			}
			// This parser must remain structural-only. Signature authentication belongs
			// to the router; changing signature bytes cannot change the parsed claims.
			altered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, 64))
			if _, ok := shadowClaims(altered); !ok {
				t.Fatal("opaque proof became a signature verifier")
			}
			client := &Client{asyncShadow: true}
			auth := authorization
			client.retainShadowAuthorization(&auth, &qtypes.OpenAIChatRequest{Stream: claims.Streamed}, claims.RouteType)
			if auth.shadowSettlement == nil {
				t.Fatal("compared metadata not retained")
			}
			// Both real authorize response targets must preserve the opaque token:
			// ordinary Authorization and the embedded Stage-D admission target.
			for _, planned := range []bool{false, true} {
				t.Run(fmt.Sprintf("admission=%t", planned), func(t *testing.T) {
					transport := liveOracleTransport(func(r *http.Request) (*http.Response, error) {
						if r.URL.Path != "/internal/gateway/authorize" {
							t.Fatalf("unexpected request %s", r.URL.Path)
						}
						return v2Reply(`{"data":` + string(tc.Authorization) + `}`), nil
					})
					client := New("https://trustedrouter.com", "test", &http.Client{Transport: transport})
					client.asyncShadow = true
					inv := &authorizationInvocation{nonce: claims.InvocationNonce}
					inv.once.Do(func() {})
					ctx := context.WithValue(t.Context(), authorizationInvocationContextKey{}, inv)
					var plan *SpendLeaseAdmissionPlan
					if planned {
						plan = &SpendLeaseAdmissionPlan{key: "key", body: []byte(`{}`)}
						inv.plans = map[string]*SpendLeaseAdmissionPlan{"key": plan}
					}
					decoded, _, err := client.authorizeAtDecodeSeamWithAdmission(ctx, "lookup", map[string]any{}, spendlease.EstimateRequest{}, plan)
					if err != nil {
						t.Fatal(err)
					}
					if string(decoded.BillingShadowBinding) != tc.Binding {
						t.Fatal("decode seam changed binding")
					}
					client.retainShadowAuthorization(decoded, &qtypes.OpenAIChatRequest{Stream: claims.Streamed}, claims.RouteType)
					if decoded.shadowSettlement == nil || !decoded.shadowSettlement.v2 {
						t.Fatal("decode seam lost compared metadata")
					}
				})
			}
		})
	}
}
