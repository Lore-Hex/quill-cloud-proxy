package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestNyteAutoAliasesAuthorizeCanonicalModel(t *testing.T) {
	for _, route := range []string{"/v1/chat/completions", "/v1/responses", "/v1/messages"} {
		for _, model := range []string{"trustedrouter/auto", "trustedrouter/auto-routing", "nyte/auto", "nyte/auto-routing"} {
			t.Run(route+"/"+model, func(t *testing.T) {
				calls := 0
				gateway := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{Transport: astraTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/internal/gateway/authorize" {
						calls++
						var body struct {
							Model string `json:"model"`
						}
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Fatal(err)
						}
						if body.Model != "trustedrouter/auto" {
							t.Fatalf("authorized model = %q", body.Model)
						}
						return astraResponse(402, `{"error":{"type":"insufficient_credits","message":"top up"}}`), nil
					}
					if r.URL.Path != "/internal/gateway/validate" {
						t.Fatalf("unexpected path %s", r.URL.Path)
					}
					return astraResponse(200, `{"data":{"workspace_id":"ws","api_key_hash":"credential"}}`), nil
				})})
				body := fmt.Sprintf(`{"model":%q,"max_tokens":1,"messages":[{"role":"user","content":"hello"}]}`, model)
				if route == "/v1/responses" {
					body = fmt.Sprintf(`{"model":%q,"input":"hello","max_output_tokens":1}`, model)
				}
				response, _ := astraRequest(t, gateway, route, body, "")
				if parseHTTPStatus(response) != 402 || calls != 1 {
					t.Fatalf("calls=%d response=%s", calls, response)
				}
			})
		}
	}
}

func TestNyteNestedModelAliases(t *testing.T) {
	for _, model := range []string{"socrates-2.0", "prometheus-3.0", "advisor", "synth", "subagent", "user-example"} {
		want := resolveFusionModelID("trustedrouter/" + model)
		if got := resolveFusionModelID("nyte/" + model); got != want {
			t.Fatalf("nested alias %s: got %s want %s", model, got, want)
		}
	}
}
