package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type shadowV2StreamTransport func(*http.Request) (*http.Response, error)

func (f shadowV2StreamTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func streamV2Fixture(t *testing.T, name string) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile("../../internal/trustedrouter/testdata/async_settlement/shadow_v2/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Variants []map[string]json.RawMessage `json:"variants"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture")
	}
	return f.Variants[0]
}

// The committed terminal literals are nonstreaming chat. Streaming controls
// change only route/stream in an UNVERIFIED local-reading token, retaining its
// fixture signature. This is not a new valid certificate and cannot certify B.
func TestShadowV2RealStreams(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	old := trustedrouter.ShadowBuildRevision
	trustedrouter.ShadowBuildRevision = strings.Repeat("a", 40)
	t.Cleanup(func() { trustedrouter.ShadowBuildRevision = old })
	for _, route := range []string{"chat.completions", "responses"} {
		for _, excluded := range []bool{false, true} {
			for _, fail := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/excluded=%v/failure=%v", route, excluded, fail), func(t *testing.T) {
					name, field := "authorize_compared", "billing_shadow_binding"
					if excluded {
						name, field = "authorize_excluded", "billing_shadow_exclusion"
					}
					var response map[string]any
					if json.Unmarshal(streamV2Fixture(t, name)["object"], &response) != nil {
						t.Fatal("projection")
					}
					proof := response[field].(string)
					parts := strings.Split(proof, ".")
					raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
					var claims map[string]any
					if json.Unmarshal(raw, &claims) != nil {
						t.Fatal("claims")
					}
					if excluded {
						claims["requested_route"], claims["requested_streamed"] = route, true
					} else {
						claims["route_type"], claims["streamed"] = route, true
					}
					raw, _ = json.Marshal(claims)
					parts[1] = base64.RawURLEncoding.EncodeToString(raw)
					proof = strings.Join(parts, ".")
					response[field] = proof
					for _, key := range []string{"authorization_id", "generation_id", "invocation_nonce", "workspace_id"} {
						response[key] = claims[key]
					}
					response["api_key_hash"], response["credit_reservation_id"] = claims["key_id"], claims["reservation_id"]
					response["billing_snapshot_hash"] = claims["snapshot_hash"]
					response["model"], response["provider"], response["endpoint_id"], response["usage_type"] = "openai/billing-v1", "openai", "openai/billing-v1@openai/prepaid", "Credits"
					reply, _ := json.Marshal(map[string]any{"data": response})
					var baseline string
					for _, enabled := range []bool{false, true} {
						flag := "off"
						if enabled {
							flag = "on"
						}
						t.Setenv("TR_ASYNC_SETTLE_SHADOW", flag)
						var body, header string
						terminals := 0
						client := &http.Client{Transport: shadowV2StreamTransport(func(r *http.Request) (*http.Response, error) {
							answer := string(reply)
							if r.URL.Path == "/internal/gateway/authorize" {
								marker := r.Header.Get("X-TR-Settlement-Shadow-Policy")
								if (marker == "shadow-v2") != enabled {
									t.Error("capability gate")
								}
							} else {
								terminals++
								raw, _ := io.ReadAll(r.Body)
								body = normalizeShadowClocks(string(raw))
								header = r.Header.Get("X-TR-Settlement-Shadow")
								if r.Header.Get("X-TR-Settlement-Mode") != "" || r.Header.Get("X-TR-Settlement-Shadow-Policy") != "" {
									t.Error("terminal headers")
								}
								answer = `{"data":{"settled":true,"cost_microdollars":4,"generation_id":"gen-c7a73498dd8a5d59a705f482070c9e56"}}`
							}
							return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(answer))}, nil
						})}
						gateway := trustedrouter.New("https://trustedrouter.com", "test", client)
						req := &types.OpenAIChatRequest{Model: "openai/billing-v1", Stream: true, StreamOptions: &types.ChatStreamOptions{IncludeUsage: true}}
						auth, err := gateway.AuthorizeWithRoute(context.Background(), "key", req, route)
						if err != nil {
							t.Fatal(err)
						}
						if gateway.AsyncSettlementNegotiated(auth) {
							t.Fatal("bound async")
						}
						var out bytes.Buffer
						serveStreaming(t.Context(), &out, shadowStreamProvider{fail: fail}, req, &types.AnthropicMessagesRequest{}, []llm.InvokeOptions{{Model: auth.Model, Provider: auth.Provider, EndpointID: auth.EndpointID}}, gateway, auth, nil, time.Now(), nil, route, "shadow-v2-stream", auth.Model)
						transcript := normalizeShadowClocks(out.String()) + "\n" + body
						if !enabled {
							baseline = transcript
							if header != "" {
								t.Fatal("off header")
							}
						} else {
							if transcript != baseline {
								t.Fatal("shadow changed stream or legacy body")
							}
							if header == "" {
								t.Fatal("missing v2 diagnostic")
							}
							raw, err := base64.RawURLEncoding.DecodeString(header)
							if err != nil {
								t.Fatal(err)
							}
							var envelope map[string]any
							if json.Unmarshal(raw, &envelope) != nil {
								t.Fatal("header")
							}
							if envelope["v"] != float64(2) || envelope["policy_version"] != "shadow-v2" {
								t.Fatal("v2 fields")
							}
							if excluded {
								fixtureName := "terminal_excluded_settle"
								if fail {
									fixtureName = "terminal_excluded_refund"
								}
								var expected map[string]any
								if json.Unmarshal(streamV2Fixture(t, fixtureName)["object"], &expected) != nil {
									t.Fatal("terminal")
								}
								expected["certificate"] = proof
								at := expected["attempt"].(map[string]any)
								at["route_type"], at["streamed"], at["selected_endpoint"], at["adapter"] = route, true, auth.EndpointID, "openai"
								expectedBytes, _ := json.Marshal(expected)
								if !bytes.Equal(raw, expectedBytes) {
									t.Fatal("stream echo differs from fixture-derived attempt")
								}
							} else {
								if envelope["variant"] != "compared" {
									t.Fatal("variant")
								}
								if fail && envelope["go_error"] != "usage_missing" {
									t.Fatal("refund diagnostic")
								}
							}
						}
						if terminals != 1 {
							t.Fatal("terminal count", terminals)
						}
					}
				})
			}
		}
	}
}
