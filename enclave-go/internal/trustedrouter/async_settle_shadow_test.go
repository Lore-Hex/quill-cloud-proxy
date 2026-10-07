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
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const shadowFixtureSHA = "68568699b000210413a20916ffa1f56093ab0223bb6a65d935ae453a9d96a28a"
const shadowFixtureRevision = "cf82c77b02a8c07191f71e954196ab90d35294d3"

func shadowFixture(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	var f map[string]json.RawMessage
	if err := json.Unmarshal(asyncFixture(t, "shadow_v1"), &f); err != nil {
		t.Fatal(err)
	}
	return f
}
func shadowAuth(t *testing.T) (*Client, *Authorization) {
	t.Helper()
	f := shadowFixture(t)
	a := fixtureAuthorization(t, true)
	if err := json.Unmarshal(f["billing_shadow_binding"], &a.BillingShadowBinding); err != nil {
		t.Fatal(err)
	}
	a.BillingSnapshot = f["billing_snapshot"]
	c := fixtureClient()
	c.asyncShadow = true
	c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
	if a.shadowSettlement == nil {
		t.Fatal("shadow metadata not retained")
	}
	return c, a
}
func shadowUsage() Usage {
	u := fixtureUsage()
	u.ShadowObservation = ObserveShadowUsage(true, "")
	return u
}
func setShadowRevision(t *testing.T) {
	t.Helper()
	old := ShadowBuildRevision
	ShadowBuildRevision = shadowFixtureRevision
	t.Cleanup(func() { ShadowBuildRevision = old })
}
func decodeShadow(t *testing.T, header string) map[string]json.RawMessage {
	t.Helper()
	raw, err := base64.RawURLEncoding.Strict().DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 8192 || len(header) > 12288 || base64.RawURLEncoding.EncodeToString(raw) != header {
		t.Fatal("wire bounds")
	}
	var value map[string]json.RawMessage
	if err = json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func TestShadowLiteralPins(t *testing.T) {
	raw := asyncFixture(t, "shadow_v1")
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != shadowFixtureSHA {
		t.Fatal("fixture bytes changed")
	}
	f := shadowFixture(t)
	wire, err := canonicalShadow(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != 2576 || len(base64.RawURLEncoding.EncodeToString(wire)) != 3435 {
		t.Fatal("literal sizes")
	}
	c, a := shadowAuth(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	public := private.Public().(ed25519.PublicKey)
	if hex.EncodeToString(public) != "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c" {
		t.Fatal("public key")
	}
	claims, err := receipt.VerifyCompactJWS(string(a.BillingShadowBinding), map[string]ed25519.PublicKey{"shadow-v1-fixture": public}, "tr-async-settle-shadow-v1")
	if err != nil {
		t.Fatal(err)
	}
	want := asyncTicketClaims{AuthorizationID: "auth-v1", GenerationID: "gen-c7a73498dd8a5d59a705f482070c9e56", WorkspaceID: "ws-v1", KeyID: "key-v1", InvocationNonce: "nonce-v1", BillingAuthority: "local", JournalRegion: "us-central1", Epoch: 1, SnapshotVersion: 1, SnapshotHash: "cb8feaf08da381f0d356dcd8ed4c6577f1d44a130e7f3b8029647fa3814872b4", RouteType: "chat.completions", Reservation: "res-v1", Origin: "typed", Iss: "router-fixture", Aud: "router-shadow", Iat: 1791244800, Exp: 1791417600}
	var got asyncTicketClaims
	if json.Unmarshal(claims, &got) != nil || got != want {
		t.Fatalf("claims: %+v", got)
	}
	if _, err = receipt.VerifyCompactJWS(string(a.BillingShadowBinding), map[string]ed25519.PublicKey{"shadow-v1-fixture": public}, "tr-async-settle-v1"); err == nil {
		t.Fatal("binding accepted as ticket")
	}
	if _, ok := parseAsyncTicketClaims(claims, 1791244801); ok {
		t.Fatal("shadow claims accepted as ticket")
	}
	c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
	if a.async != nil {
		t.Fatal("shadow bound async")
	}
	body := buildShadowEnvelope(a.shadowSettlement, shadowUsage(), "settle", shadowFixtureRevision)
	terminal := body["terminal"].(billingv1.TerminalEnvelope)
	if terminal.ChargeMicro != 2 || body["payload_hash"] != "f5a8699841e40582b2c8d49702092328ba9e63991166b95da60c90f7da5fdf32" {
		t.Fatal(body)
	}
	var literal billingv1.TerminalEnvelope
	if json.Unmarshal(f["terminal"], &literal) != nil || terminal != literal {
		t.Fatal("terminal differs")
	}
	// The literal intentionally omits eligibility defaults and pins its timing.
	body["observed"], body["handoff_prepare_us"] = map[string]any{}, 1000
	encoded, err := encodeShadow(body, len(a.shadowSettlement.raw))
	if err != nil {
		t.Fatal(err)
	}
	if encoded != base64.RawURLEncoding.EncodeToString(wire) {
		t.Fatal("complete literal mismatch")
	}
}

func TestShadowFlagPrecedence(t *testing.T) {
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "on")
	for _, flag := range []string{"", "off", "ON", " on", "on ", "true", "1", "on"} {
		t.Setenv("TR_ASYNC_SETTLE_SHADOW", flag)
		before := shadowConfigurationConflicts.Load()
		c := NewFromBootstrap(&qtypes.BootstrapData{AsyncSettleShadow: true})
		if c.asyncShadow != (flag == "on") {
			t.Fatalf("flag %q", flag)
		}
		if flag == "on" && shadowConfigurationConflicts.Load() != before+1 {
			t.Fatal("configuration conflict not counted")
		}
	}
	t.Setenv("TR_ASYNC_SETTLE_SHADOW", "")
	if err := os.Unsetenv("TR_ASYNC_SETTLE_SHADOW"); err != nil {
		t.Fatal(err)
	}
	if !NewFromBootstrap(&qtypes.BootstrapData{AsyncSettleShadow: true}).asyncShadow || NewFromEnv().asyncShadow {
		t.Fatal("boot/default")
	}
}

func TestShadowHeaderOnlyRetriesRefund(t *testing.T) {
	setShadowRevision(t)
	for _, negotiate := range []string{"off", "on"} {
		t.Run(negotiate, func(t *testing.T) {
			t.Setenv("TR_ASYNC_SETTLE_SHADOW", "on")
			t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", negotiate)
			t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", fixtureKeyring)
			_, source := shadowAuth(t)
			if negotiate == "off" {
				source.SettlementTicket = ""
				t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", "")
			}
			source.RouteType = "chat.completions"
			var bodies, headers []string
			var refundBody string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				if r.URL.Path == "/internal/gateway/authorize" {
					if r.Header.Get(asyncSettlementHeader) != "async-v1" || r.Header.Get(shadowSettlementHeader) != "" {
						t.Error("authorize headers")
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": source})
					return
				}
				if r.Header.Get(asyncSettlementHeader) != "" || len(r.Header.Values(shadowSettlementHeader)) != 1 {
					t.Error("header separation")
				}
				value := decodeShadow(t, r.Header.Get(shadowSettlementHeader))
				if r.URL.Path == "/internal/gateway/refund" {
					refundBody = string(raw)
					if string(value["go_error"]) != `"usage_missing"` || string(value["terminal"]) != "null" {
						t.Error("refund without usage")
					}
				} else {
					bodies = append(bodies, string(raw))
					headers = append(headers, r.Header.Get(shadowSettlementHeader))
					if bytes.Contains(raw, []byte("billing_snapshot")) || bytes.Contains(raw, []byte("terminal")) {
						t.Error("legacy body changed")
					}
					if len(bodies) < 3 {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = conn.Close()
						return
					}
				}
				_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":19}}`)
			}))
			defer server.Close()
			c := New(server.URL, "test", server.Client())
			a, err := c.AuthorizeWithRoute(t.Context(), "test", &qtypes.OpenAIChatRequest{Model: source.Model, IdempotencyKey: "shadow"}, "chat.completions")
			if err != nil {
				t.Fatal(err)
			}
			if a.async != nil || c.AsyncSettlementNegotiated(a) || a.shadowSettlement == nil {
				t.Fatal("async binding under shadow")
			}
			standby := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("shadow settlement changed pinned authority")
				w.WriteHeader(500)
			}))
			defer standby.Close()
			c.baseURLs = append(c.baseURLs, standby.URL)

			u := shadowUsage()
			result, err := c.Settle(t.Context(), a, u)
			if err != nil || result.CostMicrodollars != 19 || result.TrustedRouterSettlement != nil {
				t.Fatalf("legacy result: %v %v", result, err)
			}
			if len(bodies) != 3 {
				t.Fatalf("attempts %d", len(bodies))
			}
			// Identical retry in a new context also freezes timing/header.
			if _, err = c.Settle(t.Context(), a, u); err != nil {
				t.Fatal(err)
			}
			for i := range bodies {
				if bodies[i] != bodies[0] || headers[i] != headers[0] {
					t.Fatal("retry differs")
				}
			}
			// Get baseline through the real legacy sender; never derive expected bytes
			// using a second copy of the body-construction algorithm.
			baselineServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				if r.Header.Get(shadowSettlementHeader) != "" {
					t.Error("off header")
				}
				if r.URL.Path == "/internal/gateway/settle" && string(raw) != bodies[0] {
					t.Error("legacy body changed")
				}
				if r.URL.Path == "/internal/gateway/refund" && string(raw) != refundBody {
					t.Error("refund body changed")
				}
				_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":19}}`)
			}))
			defer baselineServer.Close()
			if err = c.Refund(t.Context(), a, 502, "upstream_error", 1, nil); err != nil {
				t.Fatal(err)
			}
			c.asyncShadow = false
			c.asyncNegotiate = false
			c.baseURLs = []string{baselineServer.URL}
			c.httpc = baselineServer.Client()
			if _, err = c.Settle(t.Context(), a, u); err != nil {
				t.Fatal(err)
			}
			if err = c.Refund(t.Context(), a, 502, "upstream_error", 1, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestShadowFailuresAndRefund(t *testing.T) {
	_, a := shadowAuth(t)
	for _, tc := range []struct {
		name, want string
		change     func(*Usage)
	}{
		{"missing", "usage_missing", func(u *Usage) { u.ShadowObservation.Present = false }},
		{"estimated", "usage_estimated", func(u *Usage) { u.UsageEstimated = true }},
		{"unsupported", "unsupported_observed", func(u *Usage) { u.ShadowObservation = ObserveShadowUsage(true, "flex") }},
		{"negative", "malformed_usage", func(u *Usage) { u.InputTokens = -1 }},
		{"cache", "malformed_usage", func(u *Usage) { u.CacheReadInputTokens = 2 }},
		{"reasoning", "malformed_usage", func(u *Usage) { u.ReasoningTokens = 2 }},
		{"overflow", "arithmetic_overflow", func(u *Usage) { u.InputTokens = math.MaxInt64 }},
		{"endpoint", "evaluator_failed", func(u *Usage) { u.SelectedEndpoint = "missing" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := shadowUsage()
			tc.change(&u)
			body := buildShadowEnvelope(a.shadowSettlement, u, "settle", shadowFixtureRevision)
			if body["go_error"] != tc.want || body["terminal"] != nil || body["payload_hash"] != nil {
				t.Fatal(body)
			}
			for _, size := range []int{645, 6144, 6145} {
				header, err := encodeShadow(body, size)
				if err != nil {
					t.Fatal(err)
				}
				wire := decodeShadow(t, header)
				_, full := wire["billing_snapshot"]
				if full != (size <= 6144) || string(wire["go_error"]) != fmt.Sprintf("%q", tc.want) {
					t.Fatal("failure mode lost")
				}
			}
		})
	}
	body := buildShadowEnvelope(a.shadowSettlement, shadowUsage(), "refund", shadowFixtureRevision)
	terminal, ok := body["terminal"].(billingv1.TerminalEnvelope)
	if !ok || terminal.ChargeMicro != 0 || terminal.Usage.TotalPromptTokens != 1 || terminal.Usage.OutputTokens != 1 {
		t.Fatal("refund must retain usage at zero charge", body)
	}
}

func TestShadowAllPositiveBillingCases(t *testing.T) {
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
	if len(f.Cases) != 759 {
		t.Fatal("case count")
	}
	count := 0
	for _, tc := range f.Cases {
		if tc.Charge == nil || len(tc.Snapshot) == 0 || len(tc.Raw) == 0 {
			continue
		}
		count++
		t.Run(tc.Name, func(t *testing.T) {
			_, a := shadowAuth(t)
			s, err := billingv1.ParseSnapshot(tc.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			a.shadowSettlement.snapshot = s
			a.shadowSettlement.raw = tc.Snapshot
			a.shadowSettlement.terminal.SnapshotHash, _ = billingv1.CanonicalHash(s)
			var raw billingv1.RawUsage
			if err = json.Unmarshal(tc.Raw, &raw); err != nil {
				t.Fatal(err)
			}
			u := shadowUsage()
			u.SelectedEndpoint = tc.Endpoint
			u.InputTokens = int(raw.InputTokens)
			u.OutputTokens = int(raw.OutputTokens)
			u.CacheReadInputTokens = int(raw.CacheReadTokens)
			u.CacheCreationInputTokens = int(raw.CacheCreationTokens)
			u.ReasoningTokens = int(raw.ReasoningTokens)
			body := buildShadowEnvelope(a.shadowSettlement, u, "settle", shadowFixtureRevision)
			terminal, ok := body["terminal"].(billingv1.TerminalEnvelope)
			if !ok || terminal.ChargeMicro != *tc.Charge || tc.Usage != nil && terminal.Usage != *tc.Usage {
				t.Fatal(body)
			}
		})
	}
	if count < 20 {
		t.Fatal(count)
	}
}

func TestShadowTransportSizes(t *testing.T) {
	var cases []struct {
		Candidates int                        `json:"candidates"`
		Envelope   map[string]json.RawMessage `json:"envelope"`
		Snapshot   json.RawMessage            `json:"snapshot"`
		Sizes      map[string]int             `json:"sizes"`
	}
	if err := json.Unmarshal(asyncFixture(t, "shadow_transport_v1"), &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.Candidates), func(t *testing.T) {
			_, a := shadowAuth(t)
			s, err := billingv1.ParseSnapshot(tc.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, _ := billingv1.CanonicalBytes(s)
			if len(snapshot) != tc.Sizes["snapshot"] || len(s.Candidates()) != tc.Candidates {
				t.Fatal("snapshot pin")
			}
			sh := a.shadowSettlement
			sh.snapshot = s
			sh.raw = snapshot
			if err = json.Unmarshal(tc.Envelope["billing_shadow_binding"], &sh.proof); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(tc.Envelope["terminal"], &sh.terminal); err != nil {
				t.Fatal(err)
			}
			u := shadowUsage()
			u.SelectedEndpoint = sh.terminal.SelectedEndpoint
			body := buildShadowEnvelope(sh, u, "settle", shadowFixtureRevision)
			body["observed"], body["handoff_prepare_us"] = map[string]any{}, 1000
			header, err := encodeShadow(body, len(snapshot))
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(header)
			expected, _ := canonicalShadow(tc.Envelope)
			if !bytes.Equal(raw, expected) || len(raw) != tc.Sizes["transmitted_decoded"] || len(header) != tc.Sizes["transmitted_encoded"] {
				t.Fatalf("wire differs, sizes %d/%d", len(raw), len(header))
			}
			t.Logf("candidates=%d snapshot=%d decoded=%d encoded=%d", tc.Candidates, len(snapshot), len(raw), len(header))
			if len(sh.snapshot.Candidates()) != tc.Candidates {
				t.Fatal("trimmed candidates")
			}
			// Failure preserves full/hash-only mode, and retries freeze both modes.
			setShadowRevision(t)
			c := &Client{asyncShadow: true}
			for _, missing := range []bool{false, true} {
				u.ShadowObservation.Present = !missing
				first := c.withShadowHeader(t.Context(), a, u, "settle").Value(shadowHeaderKey{})
				second := c.withShadowHeader(context.Background(), a, u, "settle").Value(shadowHeaderKey{})
				if first != second || first == nil {
					t.Fatal("header differs across retries")
				}
				wire := decodeShadow(t, first.(string))
				_, full := wire["billing_snapshot"]
				if full != (tc.Candidates != 43) {
					t.Fatal("mode")
				}
			}
		})
	}
}

func TestShadowOuterBoundsAndIsolation(t *testing.T) {
	setShadowRevision(t)
	c, a := shadowAuth(t)
	u := shadowUsage()
	// Full overflow below the inline cap must omit only billing_snapshot.
	body := buildShadowEnvelope(a.shadowSettlement, u, "settle", shadowFixtureRevision)
	body["go_revision"] = strings.Repeat("a", 7000)
	header, err := encodeShadow(body, 645)
	if err == nil {
		if _, full := decodeShadow(t, header)["billing_snapshot"]; full {
			t.Fatal("full outer overflow")
		}
	}
	body["go_revision"] = strings.Repeat("a", 9000)
	if _, err = encodeShadow(body, 645); err == nil {
		t.Fatal("remaining overflow")
	}
	before := *a
	_ = c.withShadowHeader(t.Context(), a, u, "settle")
	if !reflect.DeepEqual(before, *a) || a.async != nil {
		t.Fatal("authorization changed")
	}
	for _, proof := range []string{strings.Repeat("a", 2049), "a.b.c", string(a.BillingShadowBinding) + "=", ""} {
		if _, ok := shadowClaims(proof); ok {
			t.Fatal("invalid proof")
		}
	}
}

func TestShadowSeparateLiteralPins(t *testing.T) {
	pins := map[string]string{
		"shadow_refund_v1":              "1878d1dba29d6aaef060425161f98c902bcf20da468b042b4e1e6518d15ac343",
		"shadow_failure_v1":             "112ed39f00535b55457580a636137d2e7e6bd8fd515ad35a992da482692af441",
		"shadow_hash_only_corrected_v1": "b9c9594eac06cf89831fd0e2e149ab9eaf71f165638994578355c980589fd613",
		"shadow_hash_only_v1":           "adf9ee96c2c81723d1436110049dca24cc3a1bff108ee9d84e9912c0d8241b21",
		"shadow_retry_v1":               "a00d1fa629e1fc37b60e5623c329fbdff8479c8d79a47d482e8ff693faf58263",
		"shadow_transport_v1":           "901ba061a1fad0de82786bbe2bdd1c2a5b291e5726b46c1ede09bbad4ef3c28e",
	}
	for name, want := range pins {
		if fmt.Sprintf("%x", sha256.Sum256(asyncFixture(t, name))) != want {
			t.Fatal(name)
		}
	}
	_, a := shadowAuth(t)
	body := buildShadowEnvelope(a.shadowSettlement, Usage{}, "settle", shadowFixtureRevision)
	body["observed"], body["handoff_prepare_us"] = map[string]any{}, 1000
	header, err := encodeShadow(body, len(a.shadowSettlement.raw))
	if err != nil {
		t.Fatal(err)
	}
	var failure map[string]json.RawMessage
	_ = json.Unmarshal(asyncFixture(t, "shadow_failure_v1"), &failure)
	expected, _ := canonicalShadow(failure)
	if header != base64.RawURLEncoding.EncodeToString(expected) {
		t.Fatal("failure literal")
	}
	var retry struct {
		First, Retry map[string]json.RawMessage
		Hash         string `json:"header_sha256"`
	}
	_ = json.Unmarshal(asyncFixture(t, "shadow_retry_v1"), &retry)
	first, _ := canonicalShadow(retry.First)
	second, _ := canonicalShadow(retry.Retry)
	if !bytes.Equal(first, second) || fmt.Sprintf("%x", sha256.Sum256([]byte(base64.RawURLEncoding.EncodeToString(first)))) != retry.Hash {
		t.Fatal("retry pin")
	}
	var corrected struct {
		Snapshot json.RawMessage            `json:"rebuilt_snapshot"`
		Envelope map[string]json.RawMessage `json:"envelope"`
	}
	_ = json.Unmarshal(asyncFixture(t, "shadow_hash_only_corrected_v1"), &corrected)
	snapshot, err := billingv1.ParseSnapshot(corrected.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := billingv1.CanonicalHash(snapshot)
	if hash == a.shadowSettlement.terminal.SnapshotHash {
		t.Fatal("corrected catalog silently equals original")
	}
}

func TestShadowRefusalsPreserveLegacy(t *testing.T) {
	setShadowRevision(t)
	for _, name := range []string{"proof", "identity", "snapshot_size", "hash", "malformed_snapshot", "revision", "evaluation"} {
		t.Run(name, func(t *testing.T) {
			c, a := shadowAuth(t)
			a.shadowSettlement = nil
			switch name {
			case "proof":
				a.BillingShadowBinding = BillingSnapshotDigest(strings.Repeat("a", 2049))
			case "identity":
				a.WorkspaceID = "foreign"
			case "snapshot_size":
				a.BillingSnapshot = json.RawMessage(`{"oversized":"` + strings.Repeat("x", 65537) + `"}`)
			case "hash":
				a.BillingSnapshotHash = BillingSnapshotDigest(strings.Repeat("0", 64))
			case "malformed_snapshot":
				a.BillingSnapshot = json.RawMessage(`{"v":1,"v":2}`)
			}
			c.retainShadowAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
			if name == "revision" {
				old := ShadowBuildRevision
				ShadowBuildRevision = "unknown"
				defer func() { ShadowBuildRevision = old }()
			}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get(asyncSettlementHeader) != "" {
					t.Error("inherited authorize negotiation")
				}
				if name == "evaluation" {
					envelope := decodeShadow(t, r.Header.Get(shadowSettlementHeader))
					if string(envelope["go_error"]) != `"usage_estimated"` {
						t.Error("failed evaluation disappeared")
					}
				} else if r.Header.Get(shadowSettlementHeader) != "" {
					t.Error("invalid diagnostics emitted")
				}
				_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":31}}`)
			}))
			defer server.Close()
			c.baseURLs = []string{server.URL}
			c.httpc = server.Client()
			a.pinControlPlaneEndpoint(0)
			u := shadowUsage()
			u.UsageEstimated = true
			ctx := context.WithValue(t.Context(), asyncModeKey{}, "async-v1")
			result, err := c.Settle(ctx, a, u)
			if err != nil || result.CostMicrodollars != 31 || calls != 1 {
				t.Fatalf("legacy result changed: %v %v calls=%d", result, err, calls)
			}
		})
	}
	if _, err := canonicalShadow(map[string]any{"invalid": make(chan int)}); err == nil {
		t.Fatal("encoding failure hidden")
	}
}

func TestShadowPositiveRefundLiteral(t *testing.T) {
	_, a := shadowAuth(t)
	body := buildShadowEnvelope(a.shadowSettlement, shadowUsage(), "refund", shadowFixtureRevision)
	body["observed"], body["handoff_prepare_us"] = map[string]any{}, 1000
	header, err := encodeShadow(body, len(a.shadowSettlement.raw))
	if err != nil {
		t.Fatal(err)
	}
	var literal map[string]json.RawMessage
	if err = json.Unmarshal(asyncFixture(t, "shadow_refund_v1"), &literal); err != nil {
		t.Fatal(err)
	}
	expected, err := canonicalShadow(literal)
	if err != nil {
		t.Fatal(err)
	}
	if header != base64.RawURLEncoding.EncodeToString(expected) {
		t.Fatal("positive usage refund literal differs")
	}
	if body["payload_hash"] != "b39848e23c2c264ee89f23ab757ebf8db3b209bb5ab1235facda8924c6f89dd7" {
		t.Fatal("refund terminal hash")
	}
}
