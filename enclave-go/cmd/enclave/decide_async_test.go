package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/requesttiming"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type asyncDecideModel struct{ calls int }

func (*asyncDecideModel) InvokeStreaming(context.Context, *types.OpenAIChatRequest, *types.AnthropicMessagesRequest, io.Writer, ...llm.InvokeOptions) error {
	panic("unexpected chat invocation")
}
func (m *asyncDecideModel) InvokeDecide(context.Context, *llm.DecideRequest, ...llm.InvokeOptions) (*llm.DecideResponse, error) {
	m.calls++
	return &llm.DecideResponse{Answers: map[string]decide.Answer{"ok": {Type: "boolean", Probability: pf(0.9)}}, InputTokens: 1234, OutputTokens: 20}, nil
}

// Captured with the original writeDecideResponse and synchronous router path.
const decideSyncGolden = `{"model":"typesafe-ai/jev","answers":{"ok":{"type":"boolean","probability":0.9}},"usage":{"inputTokens":1234,"outputTokens":20},"trustedrouter":{"routing":{"fallback_attempt_count":0,"fallback_candidate_count":1,"selected_endpoint":"typesafe-ai/jev@typesafe/prepaid","selected_model":"typesafe-ai/jev","selected_provider":"typesafe","upstream_attempt_count":1}}}`

func TestHostedDecideAsyncResponse(t *testing.T) {
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "on")
	t.Setenv("TR_ASYNC_SETTLE_SHADOW", "off")
	for _, scenario := range []string{"pending", "not_offered", "absent", "images"} {
		t.Run(scenario, func(t *testing.T) {
			raw, err := os.ReadFile("../../internal/trustedrouter/testdata/async_settlement/decide_v1.json")
			if err != nil {
				t.Fatal(err)
			}
			var f struct {
				AuthorizeResponse struct {
					Data map[string]any `json:"data"`
				} `json:"authorize_response"`
				Claims    map[string]any `json:"claims"`
				SeedHex   string         `json:"seed_hex"`
				PublicKey string         `json:"public_key"`
			}
			if json.Unmarshal(raw, &f) != nil {
				t.Fatal("fixture decode failed")
			}
			parts := strings.Split(f.AuthorizeResponse.Data["settlement_ticket"].(string), ".")
			headerRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
			var header struct {
				Kid string `json:"kid"`
			}
			if json.Unmarshal(headerRaw, &header) != nil {
				t.Fatal("header decode failed")
			}
			keyring, _ := json.Marshal(map[string]string{header.Kid: f.Claims["iss"].(string) + "~" + f.PublicKey})
			t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", string(keyring))
			now := time.Now().Unix()
			f.Claims["iat"], f.Claims["exp"] = now-1, now+299
			claims, _ := json.Marshal(f.Claims)
			seed, _ := hex.DecodeString(f.SeedHex)
			signed := parts[0] + "." + base64.RawURLEncoding.EncodeToString(claims)
			f.AuthorizeResponse.Data["settlement_ticket"] = signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(signed)))
			if scenario == "not_offered" {
				f.AuthorizeResponse.Data["async_eligible"] = false
			}
			if scenario == "absent" {
				delete(f.AuthorizeResponse.Data, "async_eligible")
			}
			authorizeCalls, settleCalls := 0, 0
			gateway := trustedrouter.New("http://127.0.0.1:1", "internal", &http.Client{Transport: astraTransport(func(r *http.Request) (*http.Response, error) {
				mode := r.Header.Get("X-TR-Settlement-Mode")
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					authorizeCalls++
					want := "async-v1"
					if scenario == "images" {
						want = ""
					}
					if mode != want {
						t.Error("authorize mode differs")
					}
					encoded, _ := json.Marshal(f.AuthorizeResponse)
					return astraResponse(200, string(encoded)), nil
				case "/internal/gateway/settle":
					settleCalls++
					if scenario != "pending" {
						if mode != "" {
							t.Error("synchronous settle carried a mode header")
						}
						return astraResponse(200, `{"data":{"settled":true,"generation_id":"final-generation","cost_microdollars":55,"model":"typesafe-ai/jev","provider":"typesafe"}}`), nil
					}
					if mode != "async-v1" {
						t.Error("missing async settle header")
					}
					var body struct {
						Terminal billingv1.TerminalEnvelope `json:"terminal"`
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Fatal("settle decode failed")
					}
					if body.Terminal.RouteType != "decide" || body.Terminal.Streamed || body.Terminal.ChargeMicro != 55 || body.Terminal.Usage.TotalPromptTokens != 1234 || body.Terminal.Usage.OutputTokens != 0 || body.Terminal.SelectedEndpoint != "typesafe-ai/jev@typesafe/prepaid" {
						t.Error("terminal differs")
					}
					hash, err := billingv1.CanonicalHash(body.Terminal)
					if err != nil {
						t.Fatal(err)
					}
					encoded, _ := json.Marshal(map[string]any{"data": map[string]any{"acceptance": map[string]any{"status": "accepted", "payload_hash": hash, "settlement_status": "pending"}, "trusted_router_settlement": map[string]any{"v": 1, "settlement_id": body.Terminal.AuthorizationID + ".settle", "settlement_status": "pending", "cost_microdollars": 55, "status_url": f.AuthorizeResponse.Data["settlement_status_url"], "poll_after_ms": 1000}}})
					return astraResponse(202, string(encoded)), nil
				default:
					t.Fatal("unexpected router request")
					return nil, nil
				}
			})})
			req := &decideRequest{Model: "typesafe-ai/jev", State: json.RawMessage(`"` + strings.Repeat("x", 1500) + `"`), Questions: map[string]decide.Question{"ok": {Type: "boolean", Instructions: "ok?"}}}
			if scenario == "images" {
				req.Images = []string{"data:image/png;base64,AA=="}
			}
			specs, err := decide.Parse(req.Questions)
			if err != nil {
				t.Fatal(err)
			}
			timer := requesttiming.New(time.Now(), nil)
			timer.Start()
			ctx := requesttiming.WithTimer(t.Context(), timer)
			model := &asyncDecideModel{}
			var out bytes.Buffer
			serveHostedDecide(ctx, &out, model, req, specs, &types.OpenAIChatRequest{}, gateway, true, "test", nil, "stable")
			timer.End()
			if parseHTTPStatus(out.Bytes()) != 200 {
				t.Fatal("hosted decide failed")
			}
			if authorizeCalls != 1 || settleCalls != 1 || model.calls != 1 {
				t.Fatal("unexpected call counts")
			}
			body := strings.SplitN(out.String(), "\r\n\r\n", 2)[1]
			if scenario != "pending" {
				if body != decideSyncGolden {
					t.Error("synchronous response differs from golden")
				}
				return
			}
			var response map[string]any
			if json.Unmarshal([]byte(body), &response) != nil {
				t.Fatal("response decode failed")
			}
			pending, ok := response["trusted_router_settlement"].(map[string]any)
			if !ok || pending["settlement_status"] != "pending" || pending["cost_microdollars"] != float64(55) {
				t.Error("pending metadata missing")
			}
			// Apart from the pending member, the answer is the synchronous one.
			delete(response, "trusted_router_settlement")
			var golden map[string]any
			if json.Unmarshal([]byte(decideSyncGolden), &golden) != nil {
				t.Fatal("golden decode failed")
			}
			rest, _ := json.Marshal(response)
			want, _ := json.Marshal(golden)
			if !bytes.Equal(rest, want) {
				t.Errorf("pending answer differs beyond its settlement member: %s", rest)
			}
			if strings.Contains(body, "generation_id") {
				t.Error("pending response has a generation id")
			}
			if timer.Snapshot().SettleOutcome != "ok" {
				t.Error("settle phase differs from async chat")
			}
			var log bytes.Buffer
			writeRequestEndLog(&log, "", "POST", "/api/alpha/decide", 200, 0, out.Len(), 0, requestAuditIdentity{}, "", timer.Snapshot())
			if !strings.Contains(log.String(), `settle_outcome="ok"`) {
				t.Error("request end differs from async chat")
			}
		})
	}
}
