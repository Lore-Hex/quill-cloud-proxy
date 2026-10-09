package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type shadowStreamProvider struct {
	tier    string
	missing bool
	fail    bool
}

func (p shadowStreamProvider) InvokeStreaming(_ context.Context, _ *types.OpenAIChatRequest, _ *types.AnthropicMessagesRequest, out io.Writer, _ ...llm.InvokeOptions) error {
	if p.fail {
		return fmt.Errorf("provider failure")
	}
	usage := map[string]any{"input_tokens": 2, "output_tokens": 2}
	if p.tier != "" {
		usage["service_tier"] = p.tier
	}
	if p.missing {
		usage = nil
	}
	for _, event := range []map[string]any{
		{"type": "message_start", "message": map[string]any{"id": "msg_shadow", "type": "message", "role": "assistant", "model": "fixture", "content": []any{}, "usage": usage}},
		{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": "Hello world"}},
		{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn"}, "usage": usage},
		{"type": "message_stop"},
	} {
		raw, _ := json.Marshal(event)
		if _, err := fmt.Fprintf(out, "event: %s\ndata: %s\n\n", event["type"], raw); err != nil {
			return err
		}
	}
	return nil
}

// Only nondeterministic clock fields and random ID suffixes are normalized; every frame, usage,
// settlement field, ordering and terminator remains part of the frozen oracle.
var shadowClockFields = regexp.MustCompile(`"(?:created|created_at|completed_at)":\d+|"(?:elapsed_seconds|first_token_seconds)":(?:\d+\.?\d*(?:[eE][+-]?\d+)?)`)

var shadowRandomIDs = regexp.MustCompile(`(chatcmpl-|resp_|msg_)[0-9a-f]{32}`)

func normalizeShadowClocks(s string) string {
	s = shadowRandomIDs.ReplaceAllString(s, "${1}00000000000000000000000000000000")
	return shadowClockFields.ReplaceAllStringFunc(s, func(v string) string { return strings.SplitN(v, ":", 2)[0] + ":0" })
}

func TestShadowProviderStreamPaths(t *testing.T) {
	t.Setenv("QUILL_USAGE_HEARTBEAT", "off")
	t.Setenv("QUILL_TERMINATE_AT_CAP", "off")
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	oldRevision := trustedrouter.ShadowBuildRevision
	trustedrouter.ShadowBuildRevision = "cf82c77b02a8c07191f71e954196ab90d35294d3"
	t.Cleanup(func() { trustedrouter.ShadowBuildRevision = oldRevision })
	for _, route := range []string{"chat.completions", "responses"} {
		for _, requested := range []string{"default", "priority"} {
			for _, tier := range []string{"absent", "default", "standard", "priority", "flex", "batch", "scale", "unknown", "oversized", "missing", "failure"} {
				t.Run(route+"/"+requested+"/"+tier, func(t *testing.T) {
					reported := tier
					if tier == "absent" || tier == "missing" || tier == "failure" {
						reported = ""
					}
					if tier == "oversized" {
						reported = strings.Repeat("x", 10000)
					}
					fixture, err := os.ReadFile("../../internal/trustedrouter/testdata/async_settlement/shadow_v1.json")
					if err != nil {
						t.Fatal(err)
					}
					var f map[string]json.RawMessage
					if err = json.Unmarshal(fixture, &f); err != nil {
						t.Fatal(err)
					}
					var proof string
					_ = json.Unmarshal(f["billing_shadow_binding"], &proof)
					parts := strings.Split(proof, ".")
					raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
					var claims map[string]any
					_ = json.Unmarshal(raw, &claims)
					claims["streamed"], claims["route_type"] = true, route
					raw, _ = json.Marshal(claims)
					signed := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw)
					proof = signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), []byte(signed)))
					response := map[string]any{"authorization_id": "auth-v1", "generation_id": "gen-c7a73498dd8a5d59a705f482070c9e56", "invocation_nonce": "nonce-v1", "workspace_id": "ws-v1", "api_key_hash": "key-v1", "credit_reservation_id": "res-v1", "model": "openai/billing-v1", "provider": "openai", "endpoint_id": "openai/billing-v1@openai/prepaid", "usage_type": "Credits", "billing_shadow_binding": proof, "billing_snapshot": f["billing_snapshot"], "billing_snapshot_hash": claims["snapshot_hash"], "settlement_ticket": "opaque", "async_eligible": true}
					for _, enabled := range []bool{false, true} {
						if enabled && os.Getenv("GENERATE_SHADOW_MAIN_ORACLE") == "1" {
							continue
						}
						flag := "off"
						if enabled {
							flag = "on"
						}
						t.Setenv("TR_ASYNC_SETTLE_SHADOW", flag)
						var settleBody string
						settles := 0
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if r.URL.Path == "/internal/gateway/authorize" {
								_ = json.NewEncoder(w).Encode(map[string]any{"data": response})
								return
							}
							expectedPath := "/internal/gateway/settle"
							if tier == "failure" {
								expectedPath = "/internal/gateway/refund"
							}
							if r.URL.Path != expectedPath {
								t.Errorf("unexpected %s", r.URL.Path)
								w.WriteHeader(500)
								return
							}
							settles++
							raw, _ := io.ReadAll(r.Body)
							settleBody = normalizeShadowClocks(string(raw))
							header := r.Header.Get("X-TR-Settlement-Shadow")
							if r.Header.Get("X-TR-Settlement-Mode") != "" {
								t.Error("mode header on legacy settle")
							}
							if enabled {
								if header == "" {
									t.Error("missing diagnostic envelope")
								} else {
									decoded, e := base64.RawURLEncoding.DecodeString(header)
									if e != nil {
										t.Error(e)
									}
									var envelope struct {
										Observed struct {
											ServiceTier *string `json:"service_tier"`
											RouteType   string  `json:"route_type"`
											Streamed    bool    `json:"streamed"`
										} `json:"observed"`
										Error *string `json:"go_error"`
									}
									if e = json.Unmarshal(decoded, &envelope); e != nil {
										t.Error(e)
									}
									if envelope.Observed.RouteType != route || !envelope.Observed.Streamed {
										t.Error("observed dimensions lost")
									}
									wantTier := "unsupported"
									if reported == "" {
										wantTier = ""
									} else if reported == "default" {
										wantTier = "default"
									}
									if wantTier == "" {
										if envelope.Observed.ServiceTier != nil {
											t.Error("invented provider tier")
										}
									} else if envelope.Observed.ServiceTier == nil || *envelope.Observed.ServiceTier != wantTier {
										t.Error("sanitized provider tier used")
									}
									wantError := ""
									if wantTier == "unsupported" || requested != "default" {
										wantError = "unsupported_observed"
									}
									if tier == "missing" || tier == "failure" {
										wantError = "usage_missing"
									}
									if wantError == "" {
										if envelope.Error != nil {
											t.Errorf("ordinary error %s", *envelope.Error)
										}
									} else if envelope.Error == nil || *envelope.Error != wantError {
										t.Errorf("want %s, got %v", wantError, envelope.Error)
									}
								}
							} else if header != "" {
								t.Error("off header")
							}
							_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":4,"generation_id":"gen-c7a73498dd8a5d59a705f482070c9e56"}}`)
						}))
						gateway := trustedrouter.New(server.URL, "test", server.Client())
						req := &types.OpenAIChatRequest{Model: "openai/billing-v1", Stream: true, IdempotencyKey: "stream-shadow", ServiceTier: requested, StreamOptions: &types.ChatStreamOptions{IncludeUsage: true}}
						auth, e := gateway.AuthorizeWithRoute(t.Context(), "key", req, route)
						if e != nil {
							server.Close()
							t.Fatal(e)
						}
						if gateway.AsyncSettlementNegotiated(auth) {
							t.Fatal("shadow bound async")
						}
						var out bytes.Buffer
						serveStreaming(t.Context(), &out, shadowStreamProvider{tier: reported, missing: tier == "missing", fail: tier == "failure"}, req, &types.AnthropicMessagesRequest{}, []llm.InvokeOptions{{Model: auth.Model, Provider: auth.Provider, EndpointID: auth.EndpointID}}, gateway, auth, nil, time.Now(), nil, route, "shadow-stream", auth.Model)
						server.Close()
						if settles != 1 {
							t.Fatalf("settles=%d", settles)
						}
						if strings.Contains(out.String(), "trusted_router_settlement") {
							t.Fatal("shadow changed metadata")
						}
						transcript := normalizeShadowClocks(out.String()) + "\nLEGACY SETTLE\n" + settleBody
						path := filepath.Join("testdata", "shadow_main", route+"_"+requested+"_"+tier+".txt")
						if os.Getenv("GENERATE_SHADOW_MAIN_ORACLE") == "1" {
							if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
								t.Fatal(e)
							}
							if e = os.WriteFile(path, []byte(transcript), 0600); e != nil {
								t.Fatal(e)
							}
						}
						want, e := os.ReadFile(path)
						if e != nil {
							t.Fatal(e)
						}
						if transcript != string(want) {
							t.Fatalf("shadow=%v stream/body differ from frozen main\ngot %s\nwant %s", enabled, transcript, want)
						}
					}
				})
			}
		}
	}
}

func TestShadowStreamOraclePins(t *testing.T) {
	raw, err := os.ReadFile("testdata/shadow_main/provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != "37c89837a8a4a50d9a64fb8facd6dda34905c988d68847ed9a773ac4f24bbc51" {
		t.Fatal("frozen provenance changed")
	}
	var manifest struct {
		Files map[string]string `json:"files"`
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 44 {
		t.Fatal("stream oracle coverage changed")
	}
	for name, want := range manifest.Files {
		raw, err = os.ReadFile(filepath.Join("testdata", "shadow_main", name))
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(raw)) != want {
			t.Fatal(name)
		}
	}
}
