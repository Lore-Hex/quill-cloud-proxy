package trustedrouter

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAsyncTicketClaimRules(t *testing.T) {
	type variant struct {
		id, field string
		value     any
		wire      func([]byte) []byte
		auth      func(*Authorization)
	}
	cases := []variant{
		{id: "lifetime_301", field: "exp", value: 1791245101},
		{id: "extra_claim", field: "extra", value: "x"},
		{id: "payload_whitespace", wire: func(b []byte) []byte { return append([]byte(" "), b...) }},
		{id: "payload_reordered", wire: func(b []byte) []byte {
			return []byte(`{"streamed":false,` + strings.Replace(string(b[1:]), `,"streamed":false`, "", 1))
		}},
		{id: "bad_reservation", field: "reservation_id", value: "bad reservation"},
		{id: "lifetime_zero", field: "exp", value: 1791244800},
		{id: "future_iat", field: "iat", value: 1791244802},
		{id: "expired", field: "exp", value: 1791244801},
		{id: "epoch_zero", field: "epoch", value: 0},
		{id: "snapshot_version", field: "snapshot_version", value: 2},
		{id: "snapshot_hash_upper", field: "snapshot_hash", value: strings.Repeat("A", 64)},
		{id: "snapshot_hash_length", field: "snapshot_hash", value: strings.Repeat("a", 63)},
		{id: "billing_authority", field: "billing_authority", value: "federated"},
		{id: "settle_origin", field: "settle_origin", value: "untyped"},
		{id: "route_type", field: "route_type", value: "messages"},
		{id: "aud_binding", field: "aud", value: "other"},
		{id: "eligible_false", field: "async_eligible", value: false},
		{id: "generation_derivation", field: "generation_id", value: "gen-other", auth: func(a *Authorization) { a.GenerationID = "gen-other" }},
		{id: "reservation_missing", auth: func(a *Authorization) { a.CreditReservationID = "" }},
		{id: "reservation_binding", auth: func(a *Authorization) { a.CreditReservationID = "other" }},
	}
	for _, field := range []string{"authorization_id", "generation_id", "workspace_id", "key_id", "invocation_nonce", "billing_authority", "journal_region", "epoch", "snapshot_version", "snapshot_hash", "route_type", "streamed", "reservation_id", "settle_origin", "async_eligible", "iss", "aud", "iat", "exp"} {
		cases = append(cases, variant{id: "missing_" + field, field: field}, variant{id: "null_" + field, field: field, value: json.RawMessage("null")})
	}
	for _, field := range []string{"authorization_id", "workspace_id", "key_id", "reservation_id", "generation_id", "journal_region", "iss", "aud", "invocation_nonce"} {
		limit := 512
		if field == "authorization_id" || field == "workspace_id" || field == "key_id" || field == "reservation_id" || field == "invocation_nonce" {
			limit = 64
		}
		for _, v := range []struct{ id, value string }{{"empty", ""}, {"length", strings.Repeat("x", limit+1)}, {"characters", "bad value"}} {
			cases = append(cases, variant{id: field + "_" + v.id, field: field, value: v.value})
		}
	}
	cases = append(cases, variant{id: "nonce_punctuation", field: "invocation_nonce", value: "bad/nonce"})
	for _, field := range []string{"iat", "exp", "epoch", "snapshot_version"} {
		for _, v := range []struct {
			id    string
			value any
		}{{"string", "1"}, {"bool", true}, {"negative", -1}, {"float", json.RawMessage("1.0")}, {"overflow", json.RawMessage("9223372036854775808")}} {
			cases = append(cases, variant{id: field + "_" + v.id, field: field, value: v.value})
		}
	}
	for _, field := range []string{"streamed", "async_eligible"} {
		cases = append(cases, variant{id: field + "_integer", field: field, value: 1}, variant{id: field + "_string", field: field, value: "true"})
	}
	for _, field := range []string{"authorization_id", "generation_id", "workspace_id", "key_id", "invocation_nonce", "snapshot_hash", "route_type", "streamed"} {
		cases = append(cases, variant{id: "binding_" + field, field: field, value: map[string]any{"authorization_id": "other", "generation_id": "other", "workspace_id": "other", "key_id": "other", "invocation_nonce": "other", "snapshot_hash": strings.Repeat("a", 64), "route_type": "responses", "streamed": true}[field]})
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			c, a := fixtureClient(), fixtureAuthorization(t, true)
			c.asyncTicketKeys = map[string]ed25519.PublicKey{"test": private.Public().(ed25519.PublicKey)}
			payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(a.SettlementTicket, ".")[1])
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(payload, &fields); err != nil {
				t.Fatal(err)
			}
			if tc.field != "" {
				if tc.value == nil {
					delete(fields, tc.field)
				} else {
					fields[tc.field], _ = json.Marshal(tc.value)
				}
			}
			payload, _ = json.Marshal(fields)
			if tc.wire != nil {
				payload = tc.wire(payload)
			}
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"test","typ":"tr-async-settle-v1"}`))
			input := header + "." + base64.RawURLEncoding.EncodeToString(payload)
			a.SettlementTicket = input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))
			if tc.auth != nil {
				tc.auth(a)
			}
			c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
			if a.async != nil || c.AsyncSettlementNegotiated(a) {
				t.Fatal("malformed signed ticket bound")
			}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				raw, _ := io.ReadAll(r.Body)
				if r.Header.Get(asyncSettlementHeader) != "" || bytes.Contains(raw, []byte("billing_snapshot")) {
					t.Error("unbound ticket attempted async/snapshot sync")
				}
				_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":19}}`)
			}))
			defer server.Close()
			c.baseURLs, c.httpc = []string{server.URL}, server.Client()
			a.pinControlPlaneEndpoint(0)
			if _, err := c.Settle(t.Context(), a, fixtureUsage()); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("requests=%d", calls)
			}
		})
	}
}

func TestAsyncFinalizedDuplicate(t *testing.T) {
	for _, status := range []string{"settled", "refunded"} {
		t.Run(status, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get(asyncSettlementHeader) != "async-v1" {
					t.Error("final answer triggered fallback")
				}
				raw := bytes.ReplaceAll(asyncFixture(t, "snapshot_sync_v1"), []byte(`"settled"`), []byte(`"`+status+`"`))
				if status == "refunded" {
					raw = bytes.ReplaceAll(raw, []byte(`"cost_microdollars": 2`), []byte(`"cost_microdollars": 0`))
				}
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			a := fixtureAuthorization(t, true)
			c := bindFixture(t, a)
			c.baseURLs, c.httpc = []string{server.URL}, server.Client()
			a.pinControlPlaneEndpoint(0)
			result, err := c.Settle(t.Context(), a, fixtureUsage())
			if err != nil || result == nil || !result.AlreadySettled || result.Settled != (status == "settled") || result.FinalizationOutcome != status || !result.HasCost() || result.TrustedRouterSettlement != nil {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if _, err = c.Settle(t.Context(), a, fixtureUsage()); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("definitive duplicate made %d requests", calls)
			}
		})
	}
}

// Both admission's definitive duplicate and snapshot sync use this decoder.
func TestAsyncFinalizedDuplicateValidation(t *testing.T) {
	for _, field := range []string{"v", "settlement_id", "status_url", "cost_microdollars", "settlement_status", "acceptance_status", "payload_hash", "acceptance_settlement_status"} {
		t.Run(field, func(t *testing.T) {
			raw := asyncFixture(t, "snapshot_sync_v1")
			var response map[string]any
			if err := json.Unmarshal(raw, &response); err != nil {
				t.Fatal(err)
			}
			data := response["data"].(map[string]any)
			final := data["trusted_router_settlement"].(map[string]any)
			acceptance := data["acceptance"].(map[string]any)
			switch field {
			case "v":
				final[field] = 2
			case "cost_microdollars":
				delete(final, field)
			case "acceptance_status":
				acceptance["status"] = "accepted"
			case "payload_hash":
				acceptance[field] = strings.Repeat("0", 64)
			case "acceptance_settlement_status":
				acceptance["settlement_status"] = "refunded"
			default:
				final[field] = "wrong"
			}
			raw, _ = json.Marshal(response)
			a := fixtureAuthorization(t, true)
			bindFixture(t, a)
			body, err := buildAsyncSettlement(a.async, fixtureUsage())
			if err != nil {
				t.Fatal(err)
			}
			hash, err := billingv1.CanonicalHash(body.Terminal)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := decodeFinalSettlement(raw, hash, body.Terminal.ChargeMicro, a); err == nil || result != nil {
				t.Fatalf("invalid finalization accepted: %+v %v", result, err)
			}
		})
	}
}
