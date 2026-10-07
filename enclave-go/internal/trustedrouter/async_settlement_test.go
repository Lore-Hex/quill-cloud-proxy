package trustedrouter

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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func asyncFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/async_settlement/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func fixtureAuthorization(t *testing.T, builder bool) *Authorization {
	t.Helper()
	name := "authorize_v1"
	if builder {
		name += "_builder"
	}
	var f struct {
		Response struct {
			Data Authorization `json:"data"`
		} `json:"response"`
	}
	if err := json.Unmarshal(asyncFixture(t, name), &f); err != nil {
		t.Fatal(err)
	}
	a := &f.Response.Data
	a.WorkspaceID, a.InvocationNonce, a.UsageType, a.APIKeyHash = "ws-v1", "nonce-v1", "Credits", "key-v1"
	a.EndpointID, a.Model, a.Provider = "openai/billing-v1@openai/prepaid", "openai/billing-v1", "openai"
	return a
}
func fixtureUsage() Usage {
	return Usage{InputTokens: 1, OutputTokens: 1, RouteType: "chat.completions", SelectedEndpoint: "openai/billing-v1@openai/prepaid", SelectedModel: "openai/billing-v1", FinishReason: "stop"}
}
func fixtureClient() *Client {
	return &Client{asyncNegotiate: true, asyncClock: func() time.Time { return time.Unix(1791244801, 0) }}
}
func bindFixture(t *testing.T, a *Authorization) *Client {
	t.Helper()
	c := fixtureClient()
	c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
	if a.async == nil {
		t.Fatal("fixture failed local binding")
	}
	return c
}

func TestAsyncBuilderLiteralAndSignature(t *testing.T) {
	for _, builder := range []bool{false, true} {
		a := fixtureAuthorization(t, builder)
		bindFixture(t, a)
		parts := strings.Split(a.SettlementTicket, ".")
		public, _ := base64.RawURLEncoding.DecodeString("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w")
		signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
		if !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
			t.Fatal("literal signature invalid")
		}
		body, err := buildAsyncSettlement(a.async, fixtureUsage())
		if err != nil {
			t.Fatal(err)
		}
		if body.Terminal.ChargeMicro != 2 {
			t.Fatal(body.Terminal)
		}
		if !bytes.Equal(a.BillingSnapshot, a.async.raw) {
			t.Fatal("raw snapshot lost")
		}
		if builder {
			var literal asyncSettlementRequest
			if err := json.Unmarshal(asyncFixture(t, "request_v1"), &literal); err != nil {
				t.Fatal(err)
			}
			// Compare the complete serialized wire to the literal. The literal
			// omits observed defaults; production explicitly sends those facts.
			literal.Observed = billingv1.DefaultEligibility()
			actualJSON, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			literalJSON, err := json.Marshal(literal)
			if err != nil {
				t.Fatal(err)
			}
			var actualWire, literalWire any
			if err := json.Unmarshal(actualJSON, &actualWire); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(literalJSON, &literalWire); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actualWire, literalWire) {
				t.Fatalf("async wire differs from literal: %s", actualJSON)
			}
			if !reflect.DeepEqual(body.Terminal, literal.Terminal) || body.Ticket != literal.Ticket || body.Raw != literal.Raw {
				t.Fatalf("request differs from literal: %+v", body)
			}
			hash, _ := billingv1.CanonicalHash(body.Terminal)
			var pending struct {
				Data struct {
					Acceptance billingv1.AcceptanceOutcome `json:"acceptance"`
				} `json:"data"`
			}
			if err := json.Unmarshal(asyncFixture(t, "pending_v1"), &pending); err != nil {
				t.Fatal(err)
			}
			if hash != *pending.Data.Acceptance.PayloadHash {
				t.Fatalf("literal hash differs: %s", hash)
			}
		}
	}
}

func TestAsyncAuthorizeNegotiationGuards(t *testing.T) {
	for _, flag := range []bool{false, true} {
		for _, route := range []string{"chat.completions", "responses", "messages", "embeddings", "images", "videos", "decide"} {
			t.Run(fmt.Sprintf("%t/%s", flag, route), func(t *testing.T) {
				a := fixtureAuthorization(t, true)
				a.AdditionalCostReservationMicrodollars = 1
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					want := ""
					if flag && (route == "chat.completions" || route == "responses") {
						want = "async-v1"
					}
					if got := r.Header.Get(asyncSettlementHeader); got != want {
						t.Errorf("header %q want %q", got, want)
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": a})
				}))
				defer server.Close()
				c := New(server.URL, "internal", server.Client())
				c.asyncNegotiate = flag
				c.asyncClock = fixtureClient().asyncClock
				_, err := c.AuthorizeWithRoute(t.Context(), "key", &qtypes.OpenAIChatRequest{IdempotencyKey: "id", Model: a.Model}, route)
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestAsyncEligibilityAndTicketGuards(t *testing.T) {
	cases := map[string]func(*Client, *Authorization, *qtypes.OpenAIChatRequest){
		"key": func(_ *Client, a *Authorization, _ *qtypes.OpenAIChatRequest) { a.APIKeyHash = "other" },
		"status_url": func(_ *Client, a *Authorization, _ *qtypes.OpenAIChatRequest) {
			a.SettlementStatusURL = "https://other.invalid/status"
		},
		"flag_off":     func(c *Client, _ *Authorization, _ *qtypes.OpenAIChatRequest) { c.asyncNegotiate = false },
		"not_eligible": func(_ *Client, a *Authorization, _ *qtypes.OpenAIChatRequest) { a.AsyncEligible = false },
		"hash": func(_ *Client, a *Authorization, _ *qtypes.OpenAIChatRequest) {
			a.BillingSnapshotHash = BillingSnapshotDigest(strings.Repeat("0", 64))
		},
		"workspace":       func(_ *Client, a *Authorization, _ *qtypes.OpenAIChatRequest) { a.WorkspaceID = "other" },
		"nonce":           func(_ *Client, a *Authorization, _ *qtypes.OpenAIChatRequest) { a.InvocationNonce = "other" },
		"generation":      func(_ *Client, a *Authorization, _ *qtypes.OpenAIChatRequest) { a.GenerationID = "other" },
		"signature_shape": func(_ *Client, a *Authorization, _ *qtypes.OpenAIChatRequest) { a.SettlementTicket = "a.b.c" },
		"stream":          func(_ *Client, _ *Authorization, r *qtypes.OpenAIChatRequest) { r.Stream = true },
		"receipt":         func(_ *Client, _ *Authorization, r *qtypes.OpenAIChatRequest) { r.InferenceReceipt.Requested = true },
		"tools": func(_ *Client, _ *Authorization, r *qtypes.OpenAIChatRequest) {
			r.AdditionalCostReservationMicrodollars = 1
		},
		"tier": func(_ *Client, _ *Authorization, r *qtypes.OpenAIChatRequest) { r.ServiceTier = "priority" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := fixtureClient()
			a := fixtureAuthorization(t, true)
			r := &qtypes.OpenAIChatRequest{}
			change(c, a, r)
			c.bindAsyncAuthorization(a, r, "chat.completions")
			if c.AsyncSettlementNegotiated(a) {
				t.Fatal("ineligible authorization activated async")
			}
		})
	}
}

func TestAsyncResponseDecisionsAndRetryIdentity(t *testing.T) {
	for _, name := range []string{"pending", "duplicate", "sync_required", "conflict", "amount_conflict", "network", "server_error", "unknown", "bad_hash", "bad_amount"} {
		t.Run(name, func(t *testing.T) {
			var bodies [][]byte
			var modes []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				bodies = append(bodies, raw)
				modes = append(modes, r.Header.Get(asyncSettlementHeader))
				if r.Header.Get(asyncSettlementHeader) == "" {
					_, _ = io.WriteString(w, `{"data":{"cost_microdollars":19,"settled":true}}`)
					return
				}
				switch name {
				case "network":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				case "server_error":
					w.WriteHeader(503)
					_, _ = io.WriteString(w, `{"error":{"type":"unavailable"}}`)
					return
				case "unknown":
					_, _ = io.WriteString(w, `{"data":{}}`)
					return
				}
				fixture := name
				if name == "bad_hash" || name == "bad_amount" {
					fixture = "pending"
				}
				raw = asyncFixture(t, fixture+"_v1")
				if name == "sync_required" {
					var reasons map[string]json.RawMessage
					if err := json.Unmarshal(raw, &reasons); err != nil {
						t.Error(err)
					}
					raw = reasons["disabled"]
				}
				if name == "bad_hash" {
					raw = bytes.ReplaceAll(raw, []byte("f5a8699841e40582b2c8d49702092328ba9e63991166b95da60c90f7da5fdf32"), []byte(strings.Repeat("0", 64)))
				}
				if name == "bad_amount" {
					raw = bytes.ReplaceAll(raw, []byte(`"cost_microdollars": 2`), []byte(`"cost_microdollars": 3`))
				}
				status := 202
				if name == "sync_required" {
					status = 200
				}
				if strings.Contains(name, "conflict") {
					status = 409
				}
				w.WriteHeader(status)
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			a := fixtureAuthorization(t, true)
			c := bindFixture(t, a)
			c.baseURLs = []string{server.URL}
			c.httpc = server.Client()
			a.pinControlPlaneEndpoint(0)
			result, err := c.Settle(t.Context(), a, fixtureUsage())
			if err != nil {
				t.Fatal(err)
			}
			accepted := name == "pending" || name == "duplicate"
			if accepted {
				if result.TrustedRouterSettlement == nil || result.CostMicrodollars != 2 || result.Settled || result.GenerationID != "" || len(bodies) != 1 {
					t.Fatalf("not pending: %+v requests=%d", result, len(bodies))
				}
			} else {
				if result.TrustedRouterSettlement != nil || result.CostMicrodollars != 19 || modes[len(modes)-1] != "" {
					t.Fatalf("did not use unchanged sync fallback: %+v %v", result, modes)
				}
				retry := name == "network" || name == "server_error" || name == "unknown" || name == "bad_hash"
				want := 2
				if retry {
					want = 4
				}
				if len(bodies) != want {
					t.Fatalf("requests=%d want %d", len(bodies), want)
				}
				for i := 1; i < len(bodies)-1; i++ {
					if !bytes.Equal(bodies[0], bodies[i]) {
						t.Fatal("async retry changed payload")
					}
				}
				var legacy map[string]any
				_ = json.Unmarshal(bodies[len(bodies)-1], &legacy)
				if legacy["authorization_id"] != a.AuthorizationID || legacy["actual_input_tokens"] != float64(1) || legacy["actual_output_tokens"] != float64(1) {
					t.Fatal("sync identity/usage changed")
				}
			}
		})
	}
}

func TestAsyncExpiryAndUsageFallback(t *testing.T) {
	for _, name := range []string{"expired", "margin", "boundary", "estimated", "route", "stream", "missing_endpoint", "additional_cost", "private_tier", "service_tier", "negative", "parsed_only", "flag_disabled", "ineligible"} {
		t.Run(name, func(t *testing.T) {
			a := fixtureAuthorization(t, true)
			c := bindFixture(t, a)
			u := fixtureUsage()
			wantAsync := false
			switch name {
			case "expired":
				c.asyncClock = func() time.Time { return time.Unix(1791245100, 0) }
			case "margin":
				c.asyncClock = func() time.Time { return time.Unix(1791245071, 0) }
			case "boundary":
				c.asyncClock = func() time.Time { return time.Unix(1791245070, 0) }
				wantAsync = true
			case "estimated":
				u.UsageEstimated = true
			case "route":
				u.RouteType = "responses"
			case "stream":
				u.Streamed = true
			case "missing_endpoint":
				u.SelectedEndpoint = ""
			case "additional_cost":
				u.AdditionalCostMicrodollars = 1
			case "private_tier":
				u.PriceTierInputTokens = 1
			case "service_tier":
				u.ServiceTier = "priority"
			case "negative":
				u.InputTokens = -1
			case "parsed_only":
				a.async = nil
			case "flag_disabled":
				c.asyncNegotiate = false
			case "ineligible":
				a = fixtureAuthorization(t, true)
				a.AsyncEligible = false
				c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
			}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				async := r.Header.Get(asyncSettlementHeader) != ""
				if async != wantAsync {
					t.Errorf("async=%t want %t", async, wantAsync)
				}
				if async {
					w.WriteHeader(202)
					_, _ = w.Write(asyncFixture(t, "pending_v1"))
				} else {
					_, _ = io.WriteString(w, `{"data":{"cost_microdollars":7}}`)
				}
			}))
			defer server.Close()
			c.baseURLs = []string{server.URL}
			c.httpc = server.Client()
			a.pinControlPlaneEndpoint(0)
			if _, err := c.Settle(context.Background(), a, u); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatal(calls)
			}
		})
	}
}

func TestAsyncBuilderAllPositiveBillingCases(t *testing.T) {
	var f struct {
		Cases []struct {
			Name     string                     `json:"name"`
			Snapshot json.RawMessage            `json:"snapshot"`
			Raw      json.RawMessage            `json:"raw_usage"`
			Endpoint string                     `json:"selected_endpoint"`
			Charge   *int64                     `json:"expected_charge_micro"`
			Usage    *billingv1.NormalizedUsage `json:"expected_normalized_usage"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(asyncFixture(t, "billing_v1"), &f); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, tc := range f.Cases {
		if tc.Charge == nil || len(tc.Snapshot) == 0 || len(tc.Raw) == 0 {
			continue
		}
		count++
		t.Run(tc.Name, func(t *testing.T) {
			a := fixtureAuthorization(t, true)
			bindFixture(t, a)
			s, err := billingv1.ParseSnapshot(tc.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			a.async.snapshot = s
			a.async.raw = tc.Snapshot
			a.async.terminal.SnapshotHash, _ = billingv1.CanonicalHash(s)
			var raw billingv1.RawUsage
			if err := json.Unmarshal(tc.Raw, &raw); err != nil {
				t.Fatal(err)
			}
			u := fixtureUsage()
			u.SelectedEndpoint = tc.Endpoint
			u.InputTokens = int(raw.InputTokens)
			u.OutputTokens = int(raw.OutputTokens)
			u.CacheReadInputTokens = int(raw.CacheReadTokens)
			u.CacheCreationInputTokens = int(raw.CacheCreationTokens)
			u.ReasoningTokens = int(raw.ReasoningTokens)
			body, err := buildAsyncSettlement(a.async, u)
			if err != nil {
				t.Fatal(err)
			}
			if body.Terminal.ChargeMicro != *tc.Charge {
				t.Fatalf("builder charge %d want %d", body.Terminal.ChargeMicro, *tc.Charge)
			}
			if tc.Usage != nil && body.Terminal.Usage != *tc.Usage {
				t.Fatal("usage mismatch")
			}
		})
	}
	if count < 20 {
		t.Fatalf("only %d positive cases", count)
	}
}

func TestAsyncFlagWiring(t *testing.T) {
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	if NewFromEnv().asyncNegotiate || NewFromBootstrap(&qtypes.BootstrapData{AsyncSettleNegotiate: true}).asyncNegotiate {
		t.Fatal("explicit off ignored")
	}
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "on")
	if !NewFromEnv().asyncNegotiate || !NewFromBootstrap(nil).asyncNegotiate {
		t.Fatal("on ignored")
	}
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "true")
	if NewFromEnv().asyncNegotiate {
		t.Fatal("only explicit on enables")
	}
}

func TestAsyncFixturePins(t *testing.T) {
	for name, want := range asyncFixturePins {
		raw := asyncFixture(t, name)
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s: got %s want %s", name, got, want)
		}
	}
}

// Router origin/main f83bbaacb3e91271f7bac9ba26d826532f10962f; literal bytes.
var asyncFixturePins = map[string]string{
	"amount_conflict_v1":   "f720394ebf3e81b9741b23d8117f7c3cafee1819de8b68b3ba62220cc4562359",
	"authorize_v1":         "3f8f7b08aeb89e35bdcecd85848fc5bb95b181e103f8473459af7065a79458e0",
	"authorize_v1_builder": "01553bf972089956d27273f5bcfe38273df001ac86583b91b396b17866a6d504",
	"billing_v1":           "4aedf13e4ba30b4d1f0767f829e790c37ce3f957a39c15d1eb6aff8c8734fd81",
	"billing_v1.rules":     "ab9bac52a666efb4e268dbec210c1a598e490815bf25501ccc0759fe722ce5c4",
	"billing_v1.schema":    "d84cfd4c5fd852c736458345dcb15db2928048a6d382837ddad54f769011cfd5",
	"conflict_v1":          "e18b4707cf760a2450cc945d7a513ac77c4f9eaef213e69ae7fd182949d5c407",
	"duplicate_v1":         "ff601bf7b249d5235224d430425293da85ba9bf59e82fdf43d37f582025c88bb",
	"pending_v1":           "15bc92e3ee12d688c110ab132dc1de1f3b2c5b0117e2c5eb6f44f112fcf31c7c",
	"request_v1":           "b9cf38b1febbd0827a28832a6f9f71b1bece3ed019208f523b21625c3629c5cf",
	"status_failed_v1":     "1d4b229b03eeb38ec468570dd3b70e11434629dd9daa244ed8eaefac32b35be8",
	"status_pending_v1":    "30bc3a7bb703ef4160524269aa903a552882cdcda138221669002d59563c6290",
	"status_refunded_v1":   "ad00e267dce089140deadd0fbb2cadc4603c990c8d76fcd5acafc9308bee6707",
	"status_settled_v1":    "d0ec592ee60f6a79f721b0af780b50dc2530e19a54cb0a328ea7497307b28876",
	"sync_required_v1":     "5b3d999ea9ff61829d0494de2f473787cc9bdace9bdc39d36e22ec1d2089fddb",
}

func TestAsyncAllSyncRequiredReasons(t *testing.T) {
	var reasons map[string]json.RawMessage
	if err := json.Unmarshal(asyncFixture(t, "sync_required_v1"), &reasons); err != nil {
		t.Fatal(err)
	}
	reasons["future_reason"] = json.RawMessage(`{"data":{"acceptance":{"status":"sync_required"},"reason":"future_reason"}}`)
	for reason, reply := range reasons {
		t.Run(reason, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get(asyncSettlementHeader) != "" {
					_, _ = w.Write(reply)
				} else {
					_, _ = io.WriteString(w, `{"data":{"cost_microdollars":23}}`)
				}
			}))
			defer server.Close()
			a := fixtureAuthorization(t, true)
			c := bindFixture(t, a)
			c.baseURLs = []string{server.URL}
			c.httpc = server.Client()
			a.pinControlPlaneEndpoint(0)
			result, err := c.Settle(t.Context(), a, fixtureUsage())
			if err != nil {
				t.Fatal(err)
			}
			if result.TrustedRouterSettlement != nil || result.CostMicrodollars != 23 || calls != 2 {
				t.Fatalf("sync_required treated as accepted: %+v %d", result, calls)
			}
		})
	}
}

func TestAsyncFallbackNeverReentersWithChangedPayload(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get(asyncSettlementHeader) != "" {
			if calls > 1 {
				t.Error("async restarted after conflict")
			}
			w.WriteHeader(409)
			_, _ = w.Write(asyncFixture(t, "conflict_v1"))
			return
		}
		_, _ = io.WriteString(w, `{"data":{"cost_microdollars":7}}`)
	}))
	defer server.Close()
	a := fixtureAuthorization(t, true)
	c := bindFixture(t, a)
	c.baseURLs = []string{server.URL}
	c.httpc = server.Client()
	a.pinControlPlaneEndpoint(0)
	u := fixtureUsage()
	if _, err := c.Settle(t.Context(), a, u); err != nil {
		t.Fatal(err)
	}
	u.InputTokens++
	if _, err := c.Settle(t.Context(), a, u); err != nil {
		t.Fatal(err)
	}
}

func TestAsyncMalformedAdditionsRemainDormant(t *testing.T) {
	for _, raw := range []string{`{"async_eligible":"yes","billing_snapshot_hash":42}`, `{"async_eligible":{},"billing_snapshot_hash":[]}`} {
		var a Authorization
		if err := json.Unmarshal([]byte(raw), &a); err != nil {
			t.Fatal("new fields broke legacy decode", err)
		}
		if bool(a.AsyncEligible) || a.BillingSnapshotHash != "" || a.async != nil {
			t.Fatal("malformed additions activated")
		}
	}
}

func TestAsyncRefundRemainsLegacy(t *testing.T) {
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/gateway/refund" || r.Header.Get(asyncSettlementHeader) != "" {
			t.Error("refund negotiated async")
		}
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, raw)
		_, _ = io.WriteString(w, `{"data":{"cost_microdollars":0,"settled":true}}`)
	}))
	defer server.Close()
	a := fixtureAuthorization(t, true)
	c := bindFixture(t, a)
	c.baseURLs = []string{server.URL}
	c.httpc = server.Client()
	a.pinControlPlaneEndpoint(0)
	for _, flag := range []bool{true, false} {
		c.asyncNegotiate = flag
		if _, err := c.RefundDetailedAttributed(t.Context(), a, 502, "upstream_error", 1, nil, RefundAttribution{User: "user", SessionID: "session"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("refund body changed under flag")
	}
}

func TestAsyncPendingRequiresExplicitCostAndPoll(t *testing.T) {
	for _, field := range []string{"cost_microdollars", "poll_after_ms"} {
		for _, kind := range []string{"missing", "null", "zero"} {
			t.Run(field+"/"+kind, func(t *testing.T) {
				const hash = "f5a8699841e40582b2c8d49702092328ba9e63991166b95da60c90f7da5fdf32"
				var reply map[string]any
				if err := json.Unmarshal(asyncFixture(t, "pending_v1"), &reply); err != nil {
					t.Fatal(err)
				}
				pending := reply["data"].(map[string]any)["trusted_router_settlement"].(map[string]any)
				pending["cost_microdollars"] = 0
				switch kind {
				case "missing":
					delete(pending, field)
				case "null":
					pending[field] = nil
				case "zero":
					pending[field] = 0
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202); _ = json.NewEncoder(w).Encode(reply) }))
				defer server.Close()
				c := New(server.URL, "test", server.Client())
				a := fixtureAuthorization(t, true)
				result, _, _ := c.asyncSettlementAttempt(t.Context(), 0, []byte(`{}`), hash, 0, a)
				if (result != nil) != (kind == "zero") {
					t.Fatalf("ambiguous zero accepted or explicit zero lost: %+v", result)
				}
			})
		}
	}
}
