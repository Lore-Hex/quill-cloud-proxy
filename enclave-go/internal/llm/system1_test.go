package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/directproviders"
)

func TestSystem1TierKeyWireAndUsage(t *testing.T) {
	for _, provider := range []string{"system1models", "system1models-eu"} {
		t.Run(provider, func(t *testing.T) {
			tier := system1Tier(provider)
			spec, ok := directproviders.Lookup(provider)
			if !ok || spec.SecretName != "trustedrouter-system1models-"+tier+"-api-key" {
				t.Fatal("regional secret not isolated")
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/systemone" || r.Header.Get("S1-Region") != tier || r.Header.Get("Authorization") != "Bearer test-"+tier {
					t.Error("incorrect path, tier or regional credential")
				}
				var wire DecideRequest
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Fatal(err)
				}
				if wire.Model != "s1-vision" || wire.Questions["q"].Type != "noul" || len(wire.Images) != 1 {
					t.Error("wire translation lost model/question/image")
				}
				w.Header().Set("S1-Region", tier)
				_ = json.NewEncoder(w).Encode(map[string]any{"model": "s1-vision", "tier": tier, "answers": map[string]any{"q": map[string]any{"type": "noul", "noul": 0.9}}, "usage": map[string]int{"input_tokens": 420, "output_tokens": 0, "decisions": 1}})
			}))
			defer server.Close()
			client := &openAICompatibleClient{provider: provider, baseURL: server.URL + "/v1", apiKey: "test-" + tier, httpc: server.Client()}
			req := &DecideRequest{Model: provider + "/s1-vision", State: json.RawMessage(`"test"`), Questions: map[string]decide.Question{"q": {Type: decide.TypeBoolean, Instructions: "Is it red?"}}, Images: []string{"data:image/png;base64,test"}}
			result, err := client.InvokeDecide(context.Background(), req, InvokeOptions{Provider: provider, UpstreamModel: "s1-vision"})
			if err != nil {
				t.Fatal(err)
			}
			if result.InputTokens != 420 || result.OutputTokens != 0 || result.Answers["q"].Type != decide.TypeBoolean {
				t.Fatalf("incorrect result: %+v", result)
			}
			if req.Questions["q"].Type != decide.TypeBoolean {
				t.Fatal("mutated caller request")
			}
		})
	}
}

func TestSystem1RejectsAmbiguousUsageAndTier(t *testing.T) {
	for _, change := range []string{"header", "tier", "model", "input_tokens", "output_tokens", "decisions", "missing_usage"} {
		t.Run(change, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("S1-Region", "eu")
				usage := map[string]int{"input_tokens": 100, "output_tokens": 0, "decisions": 1}
				body := map[string]any{"model": "s1-fast", "tier": "eu", "answers": map[string]any{}, "usage": usage}
				switch change {
				case "header":
					w.Header().Set("S1-Region", "global")
				case "tier":
					body["tier"] = "global"
				case "model":
					body["model"] = "s1-pro"
				case "input_tokens":
					usage[change] = 0
				case "output_tokens":
					usage[change] = 1
				case "decisions":
					usage[change] = 2
				case "missing_usage":
					delete(body, "usage")
				}
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			client := &openAICompatibleClient{provider: "system1models-eu", baseURL: server.URL, apiKey: "test", httpc: server.Client()}
			_, err := client.InvokeDecide(context.Background(), &DecideRequest{Model: "s1-fast"})
			if DecideErrorClass(err) != DecideErrDecode {
				t.Fatalf("ambiguous response accepted: %v", err)
			}
		})
	}
}
