package trustedrouter

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAuthorizationGatewayRegionIsLocalAndSeparateFromAccounting(t *testing.T) {
	for _, region := range []string{"eu-west-1", "eu-west-3", "uaenorth", "australiaeast", "europe-west4", ""} {
		for _, route := range []string{"chat.completions", "embeddings"} {
			t.Run(region+"/"+route, func(t *testing.T) {
				var request map[string]any
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if request["region"] != region {
						t.Errorf("authorize region = %v, want %q", request["region"], region)
					}
					if err := json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
						"authorization_id": "auth-region", "region": "us-central1",
						"gateway_region": "forged-wire-region", "GatewayRegion": "forged-field-region",
						"model": "test/model", "provider": "test", "usage_type": "Credits",
						"estimated_cost_microdollars": 17,
					}}); err != nil {
						t.Error(err)
					}
				}))
				defer server.Close()
				t.Setenv("TR_REGION", "")
				t.Setenv("TR_CONTROL_PLANE_BASE_URL", "")
				client := NewFromBootstrap(&qtypes.BootstrapData{
					Region: region, TrustedRouterBaseURL: server.URL,
					TrustedRouterInternalToken: "test-internal",
				})
				client.httpc = server.Client()
				var auth *Authorization
				var err error
				if route == "embeddings" {
					auth, err = client.AuthorizeEmbeddings(t.Context(), "test-key", &qtypes.EmbeddingRequest{Model: "test/model"}, 1)
				} else {
					auth, err = client.Authorize(t.Context(), "test-key", &qtypes.OpenAIChatRequest{Model: "test/model"})
				}
				if err != nil {
					t.Fatal(err)
				}
				if auth.GatewayRegion != region || auth.Region != "us-central1" || auth.EstimatedCostMicrodollars != 17 {
					t.Fatalf("gateway=%q accounting=%q cost=%d", auth.GatewayRegion, auth.Region, auth.EstimatedCostMicrodollars)
				}
				usage := Usage{InputTokens: 11, OutputTokens: 3, CacheReadInputTokens: 7}
				withOrigin, err := buildSettleBody(t.Context(), auth, usage)
				if err != nil {
					t.Fatal(err)
				}
				accountingOnly := *auth
				accountingOnly.GatewayRegion = ""
				withoutOrigin, err := buildSettleBody(t.Context(), &accountingOnly, usage)
				if err != nil || !bytes.Equal(withOrigin, withoutOrigin) {
					t.Fatal("gateway provenance changed settlement bytes")
				}
				encoded, err := json.Marshal(auth)
				if err != nil {
					t.Fatal(err)
				}
				var wire map[string]any
				if err := json.Unmarshal(encoded, &wire); err != nil {
					t.Fatal(err)
				}
				for _, key := range []string{"gateway_region", "GatewayRegion"} {
					if _, ok := wire[key]; ok {
						t.Fatalf("local provenance leaked into accounting wire: %q", key)
					}
				}
			})
		}
	}
}
