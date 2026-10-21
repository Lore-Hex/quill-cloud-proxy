//go:build llm_multi

package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

func TestSystem1PublicRebrandUsesExistingBootstrapClients(t *testing.T) {
	for _, suffix := range []string{"", "-eu"} {
		t.Run(suffix, func(t *testing.T) {
			tier := "global"
			if suffix == "-eu" {
				tier = "eu"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("S1-Region") != tier || r.Header.Get("Authorization") != "Bearer test-"+tier {
					t.Error("rebrand selected the wrong regional credential")
				}
				var body DecideRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Model != "s1-fast" {
					t.Error("rebrand changed the native model")
				}
				w.Header().Set("S1-Region", tier)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"model": "s1-fast", "tier": tier,
					"answers": map[string]any{"q": map[string]any{"type": "noul", "noul": 0.9}},
					"usage":   map[string]int{"input_tokens": 10, "output_tokens": 0, "decisions": 1},
				})
			}))
			defer server.Close()
			internalProvider := "system1models" + suffix
			client := &multiClient{direct: map[string]*openAICompatibleClient{
				internalProvider: {provider: internalProvider, baseURL: server.URL, apiKey: "test-" + tier, httpc: server.Client()},
			}}
			publicProvider := "decisionmodelsio" + suffix
			request := &DecideRequest{Model: publicProvider + "/s1-fast", State: json.RawMessage(`"test"`), Questions: map[string]decide.Question{"q": {Type: decide.TypeBoolean, Instructions: "Is it red?"}}}
			result, err := client.InvokeDecide(context.Background(), request, InvokeOptions{Provider: publicProvider, UpstreamModel: "s1-fast"})
			if err != nil || result.InputTokens != 10 {
				t.Fatalf("new provider did not use the existing client: result=%+v err=%v", result, err)
			}
		})
	}
}
