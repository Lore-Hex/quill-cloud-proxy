package trustedrouter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type decideAsyncFixture struct {
	AuthorizeRequest  json.RawMessage `json:"authorize_request"`
	AuthorizeResponse struct {
		Data Authorization `json:"data"`
	} `json:"authorize_response"`
	Claims        map[string]any             `json:"claims"`
	Now           int64                      `json:"now"`
	PublicKey     string                     `json:"public_key"`
	SeedHex       string                     `json:"seed_hex"`
	SettleRequest json.RawMessage            `json:"settle_request"`
	Terminal      billingv1.TerminalEnvelope `json:"terminal"`
}

func loadDecideAsync(t *testing.T) (*Client, *Authorization, decideAsyncFixture) {
	t.Helper()
	var f decideAsyncFixture
	if err := json.Unmarshal(asyncFixture(t, "decide_v1"), &f); err != nil {
		t.Fatal("fixture decode failed")
	}
	public, err := base64.RawURLEncoding.DecodeString(f.PublicKey)
	if err != nil {
		t.Fatal("fixture public key decode failed")
	}
	var header struct {
		Kid string `json:"kid"`
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(f.AuthorizeResponse.Data.SettlementTicket, ".")[0])
	if json.Unmarshal(raw, &header) != nil {
		t.Fatal("fixture header decode failed")
	}
	c := New("http://127.0.0.1:1", "internal", &http.Client{})
	c.asyncNegotiate = true
	c.asyncClock = func() time.Time { return time.Unix(f.Now, 0) }
	c.asyncTicketKeys = map[string]asyncTicketKey{header.Kid: {public: ed25519.PublicKey(public), issuer: f.Claims["iss"].(string)}}
	return c, &f.AuthorizeResponse.Data, f
}

func decideAsyncUsage() Usage {
	return Usage{InputTokens: 1234, RouteType: "decide", SelectedEndpoint: "typesafe-ai/jev@typesafe/prepaid", FinishReason: "stop"}
}

func canonicalDecideJSON(t *testing.T, raw []byte) []byte {
	t.Helper()
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		t.Fatal("invalid JSON")
	}
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal("cannot encode JSON")
	}
	return out
}

func requireDecideBinding(t *testing.T, c *Client, a *Authorization) {
	t.Helper()
	c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "decide")
	if !c.AsyncSettlementNegotiated(a) {
		t.Fatal("hosted decide did not bind")
	}
}

func TestDecideAsyncFixture(t *testing.T) {
	c, a, f := loadDecideAsync(t)
	public, _ := base64.RawURLEncoding.DecodeString(f.PublicKey)
	keys := map[string]ed25519.PublicKey{}
	for id := range c.asyncTicketKeys {
		keys[id] = public
	}
	raw, _, err := receipt.VerifyCompactJWSWithKey(a.SettlementTicket, keys, "tr-async-settle-v1")
	if err != nil {
		t.Fatal("fixture signature verification failed")
	}
	claims, ok := parseAsyncTicketClaims(raw, f.Now)
	if !ok || claims.RouteType != "decide" || claims.Streamed {
		t.Fatal("fixture claims refused")
	}
	requireDecideBinding(t, c, a)
	body, err := buildAsyncSettlement(a.async, decideAsyncUsage())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(body)
	if !bytes.Equal(canonicalDecideJSON(t, encoded), canonicalDecideJSON(t, f.SettleRequest)) {
		t.Fatal("complete settle body differs from fixture")
	}
	if body.Terminal != f.Terminal {
		t.Fatal("terminal differs from fixture")
	}
}

func decideWireResponse(status int, value any) *http.Response {
	raw, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}
}

func TestDecideAsyncAuthorizeWire(t *testing.T) {
	if asyncCohort("decide") {
		t.Fatal("decide entered shadow cohort")
	}
	for _, name := range []string{"hosted", "images", "embeddings", "native", "off", "no_keys", "shadow", "shadow_native"} {
		t.Run(name, func(t *testing.T) {
			c, a, f := loadDecideAsync(t)
			if name == "off" {
				c.asyncNegotiate = false
			}
			if name == "no_keys" {
				c.asyncTicketKeys = nil
			}
			if name == "shadow" || name == "shadow_native" {
				c.asyncShadow = true
				f.Claims["aud"], f.Claims["async_eligible"] = "router-shadow", false
				f.Claims["exp"] = f.Claims["iat"].(float64) + 172800
				payload, _ := json.Marshal(f.Claims)
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"test","typ":"tr-async-settle-shadow-v1"}`))
				a.BillingShadowBinding = BillingSnapshotDigest(header + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)))
			}
			var bodies [][]byte
			var modes [][]string
			c.httpc = &http.Client{Transport: asyncRoundTripper(func(r *http.Request) (*http.Response, error) {
				b, _ := io.ReadAll(r.Body)
				bodies = append(bodies, b)
				modes = append(modes, r.Header.Values(asyncSettlementHeader))
				if len(r.Header.Values(shadowSettlementHeader)) != 0 {
					t.Error("decide acquired shadow header")
				}
				return decideWireResponse(200, map[string]any{"data": a}), nil
			})}
			req := &qtypes.EmbeddingRequest{Model: a.Model, IdempotencyKey: "stable", User: "user", SessionID: "session"}
			route := "decide"
			if name == "embeddings" {
				route = "embeddings"
			}
			call := func() (*Authorization, error) {
				ctx := WithAuthorizationInvocation(t.Context())
				invocation := explicitAuthorizationInvocation(ctx)
				invocation.once.Do(func() { invocation.nonce = a.InvocationNonce })
				req.Tags = nil
				if name == "native" || name == "shadow_native" {
					return c.AuthorizeWithRoute(ctx, "test", &qtypes.OpenAIChatRequest{Model: a.Model, IdempotencyKey: "stable"}, "decide")
				}
				if name == "images" {
					return c.AuthorizeEmbeddingsWithRouteSync(ctx, "test", req, 1234, route)
				}
				return c.AuthorizeEmbeddingsWithRoute(ctx, "test", req, 1234, route)
			}
			got, err := call()
			if err != nil {
				t.Fatal("authorize failed")
			}
			want := name == "hosted"
			if c.AsyncSettlementNegotiated(got) != want {
				t.Error("unexpected binding")
			}
			if got.shadowSettlement != nil {
				t.Error("decide retained shadow state")
			}
			if want {
				if len(modes[0]) != 1 || modes[0][0] != "async-v1" {
					t.Error("expected exactly one async mode header")
				}
			} else if len(modes[0]) != 0 {
				t.Error("unexpected async mode header")
			}
			c.asyncNegotiate = false
			if _, err = call(); err != nil {
				t.Fatal("baseline authorize failed")
			}
			if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
				t.Error("authorize body changed")
			}
		})
	}
}

func signDecideClaims(t *testing.T, a *Authorization, f decideAsyncFixture) {
	t.Helper()
	seed, err := hex.DecodeString(f.SeedHex)
	if err != nil {
		t.Fatal("seed decode failed")
	}
	payload, _ := json.Marshal(f.Claims)
	header := strings.Split(a.SettlementTicket, ".")[0]
	input := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	a.SettlementTicket = input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(input)))
}

func TestDecideAsyncBindingFallback(t *testing.T) {
	// A valid control ensures the refusals below exercise an enabled live route.
	c, a, _ := loadDecideAsync(t)
	requireDecideBinding(t, c, a)
	cases := []string{"false", "absent", "signature", "chat_ticket", "decide_ticket_on_chat", "streamed", "reservation", "authorization", "generation", "workspace", "key", "nonce", "expired", "snapshot_hash", "ticket_hash", "receipt", "spend_lease", "custom_model", "native_batch", "status_url", "issuer", "audience", "snapshot_parse"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			c, a, f := loadDecideAsync(t)
			route := "decide"
			switch name {
			case "false", "absent":
				a.AsyncEligible = false
			case "signature":
				parts := strings.Split(a.SettlementTicket, ".")
				parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
				a.SettlementTicket = strings.Join(parts, ".")
			case "chat_ticket":
				f.Claims["route_type"] = "chat.completions"
			case "decide_ticket_on_chat":
				route = "chat.completions"
			case "streamed":
				f.Claims["streamed"] = true
			case "reservation":
				a.CreditReservationID = "different"
			case "authorization":
				a.AuthorizationID = "different"
			case "generation":
				a.GenerationID = "different"
			case "workspace":
				a.WorkspaceID = "different"
			case "key":
				a.APIKeyHash = "different"
			case "nonce":
				a.InvocationNonce = "different"
			case "expired":
				c.asyncClock = func() time.Time { return time.Unix(f.Now+300, 0) }
			case "snapshot_hash":
				a.BillingSnapshotHash = BillingSnapshotDigest(strings.Repeat("0", 64))
			case "ticket_hash":
				f.Claims["snapshot_hash"] = strings.Repeat("0", 64)
			case "receipt":
				a.ReceiptFeeBasisPoints = 1
			case "spend_lease":
				a.SpendLease = &spendlease.Response{}
			case "custom_model":
				a.CustomModel = &CustomModel{}
			case "native_batch":
				a.NativeBatchEligible = true
			case "status_url":
				a.SettlementStatusURL = "/other"
			case "issuer":
				f.Claims["iss"] = "different"
			case "audience":
				f.Claims["aud"] = "different"
			case "snapshot_parse":
				a.BillingSnapshot = json.RawMessage(`{}`)
			}
			if name == "chat_ticket" || name == "streamed" || name == "ticket_hash" || name == "issuer" || name == "audience" {
				signDecideClaims(t, a, f)
			}
			if name == "streamed" {
				raw, _ := json.Marshal(f.Claims)
				if _, valid := parseAsyncTicketClaims(raw, f.Now); valid {
					t.Error("streamed decide claims accepted")
				}
			}
			c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, route)
			if a.async != nil {
				t.Fatal("invalid authorization bound")
			}
			a.pinControlPlaneEndpoint(0)
			var bodies [][]byte
			c.httpc = &http.Client{Transport: asyncRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get(asyncSettlementHeader) != "" {
					t.Error("fallback used async mode")
				}
				raw, _ := io.ReadAll(r.Body)
				bodies = append(bodies, raw)
				return decideWireResponse(200, map[string]any{"data": map[string]any{"settled": true, "cost_microdollars": 55}}), nil
			})}
			usage := decideAsyncUsage()
			if _, err := c.Settle(t.Context(), a, usage); err != nil {
				t.Fatal("fallback settle failed")
			}
			c.asyncNegotiate = false
			if _, err := c.Settle(t.Context(), a, usage); err != nil {
				t.Fatal("baseline settle failed")
			}
			if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
				t.Error("ordinary settle bytes changed")
			}
		})
	}
}

func TestDecideAsyncSettle(t *testing.T) {
	for _, name := range []string{"pending", "sync_required", "unsupported_cohort", "estimated", "empty_endpoint"} {
		t.Run(name, func(t *testing.T) {
			c, a, _ := loadDecideAsync(t)
			requireDecideBinding(t, c, a)
			a.pinControlPlaneEndpoint(0)
			usage := decideAsyncUsage()
			if name == "estimated" {
				usage.UsageEstimated = true
			}
			if name == "empty_endpoint" {
				usage.SelectedEndpoint = ""
			}
			var bodies [][]byte
			var modes []string
			c.httpc = &http.Client{Transport: asyncRoundTripper(func(r *http.Request) (*http.Response, error) {
				raw, _ := io.ReadAll(r.Body)
				bodies = append(bodies, raw)
				mode := r.Header.Get(asyncSettlementHeader)
				modes = append(modes, mode)
				if mode == "async-v1" {
					if name != "pending" {
						return decideWireResponse(200, map[string]any{"data": map[string]any{"acceptance": map[string]any{"status": "sync_required"}, "reason": name}}), nil
					}
					var body asyncSettlementRequest
					if json.Unmarshal(raw, &body) != nil {
						t.Fatal("settle decode failed")
					}
					hash, _ := billingv1.CanonicalHash(body.Terminal)
					return decideWireResponse(202, map[string]any{"data": map[string]any{"acceptance": map[string]any{"status": "accepted", "payload_hash": hash, "settlement_status": "pending"}, "trusted_router_settlement": map[string]any{"v": 1, "settlement_id": a.AuthorizationID + ".settle", "settlement_status": "pending", "cost_microdollars": 55, "status_url": a.SettlementStatusURL, "poll_after_ms": 1000}}}), nil
				}
				return decideWireResponse(200, map[string]any{"data": map[string]any{"settled": true, "cost_microdollars": 55}}), nil
			})}
			got, err := c.Settle(context.Background(), a, usage)
			if err != nil || got == nil {
				t.Fatal("settle failed")
			}
			if !got.HasCost() || got.CostMicrodollars != 55 {
				t.Error("cost missing")
			}
			switch name {
			case "pending":
				if len(modes) != 1 || modes[0] != "async-v1" || got.TrustedRouterSettlement == nil || got.GenerationID != "" {
					t.Error("pending result differs")
				}
			case "estimated", "empty_endpoint":
				if len(modes) != 1 || modes[0] != "" || got.TrustedRouterSettlement != nil {
					t.Error("expected ordinary settle")
				}
			default:
				if len(modes) != 2 || modes[0] != "async-v1" || modes[1] != "sync" || !bytes.Equal(bodies[0], bodies[1]) {
					t.Error("snapshot sync did not preserve frozen bytes")
				}
			}
		})
	}
}
