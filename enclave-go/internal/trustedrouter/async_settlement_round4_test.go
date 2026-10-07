package trustedrouter

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func assertAsyncUnboundLegacy(t *testing.T, c *Client, a *Authorization) {
	t.Helper()
	c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
	if a.async != nil || c.AsyncSettlementNegotiated(a) {
		t.Fatal("ticket bound")
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
}

func signIssuerTicket(t *testing.T, a *Authorization, private ed25519.PrivateKey, kid, issuer string) {
	t.Helper()
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(a.SettlementTicket, ".")[1])
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	fields["iss"], _ = json.Marshal(issuer)
	payload, _ = json.Marshal(fields)
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": kid, "typ": "tr-async-settle-v1"})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	a.SettlementTicket = input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))
}

func TestAsyncTicketIssuerBinding(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	encoded := base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	for _, tc := range []struct{ name, claim, configured string }{
		{"wrong_issuer", "wrong-issuer", "router-fixture"},
		{"empty_issuer", "", "router-fixture"},
		{"trailing_space", "router-fixture ", "router-fixture"},
		{"kid_remapped", "router-fixture", "other-issuer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, _ := json.Marshal(map[string]string{"test": tc.configured + "~" + encoded})
			t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", string(config))
			c, a := fixtureClient(), fixtureAuthorization(t, true)
			signIssuerTicket(t, a, private, "test", tc.claim)
			assertAsyncUnboundLegacy(t, c, a)
		})
	}
	// Deliberately reuse the same public key under two kids: only key-ID-specific
	// issuer policy can distinguish the two signatures.
	t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", `{"first":"issuer-first~`+encoded+`","second":"issuer-second~`+encoded+`"}`)
	for _, kid := range []string{"first", "second"} {
		for _, issuer := range []string{"issuer-first", "issuer-second"} {
			t.Run(kid+"/"+issuer, func(t *testing.T) {
				c, a := fixtureClient(), fixtureAuthorization(t, true)
				signIssuerTicket(t, a, private, kid, issuer)
				if issuer != "issuer-"+kid {
					assertAsyncUnboundLegacy(t, c, a)
					return
				}
				c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
				if !c.AsyncSettlementNegotiated(a) {
					t.Fatal("own issuer rejected")
				}
			})
		}
	}
}

func TestAsyncKeyringMalformedEntries(t *testing.T) {
	const encoded = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"
	for _, tc := range []struct{ name, entry string }{
		{"without_issuer", encoded}, {"empty_issuer", "~" + encoded},
		{"space_issuer", "router-fixture ~" + encoded}, {"extra_separator", "router-fixture~~" + encoded},
		{"invalid_key", "router-fixture~bad"}, {"padded_key", "router-fixture~" + encoded + "="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, _ := json.Marshal(map[string]string{"async-v1-fixture": "router-fixture~" + encoded, "bad": tc.entry})
			assertMalformedAsyncKeyring(t, string(config))
		})
	}
	for _, tc := range []struct{ name, raw string }{
		{"duplicate_kid", `{"test":"one~` + encoded + `","test":"two~` + encoded + `"}`},
		{"empty_kid", `{"":"router-fixture~` + encoded + `"}`},
		{"trailing_json", fixtureKeyring + `{}`}, {"null_entry", `{"test":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) { assertMalformedAsyncKeyring(t, tc.raw) })
	}
}

func assertMalformedAsyncKeyring(t *testing.T, raw string) {
	t.Helper()
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "on")
	t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", raw)
	c := NewFromBootstrap(&qtypes.BootstrapData{AsyncSettleTicketPublicKeys: fixtureKeyring})
	if len(c.asyncTicketKeys) != 0 {
		t.Fatal("partial or malformed keyring usable")
	}
	a := fixtureAuthorization(t, true)
	c.asyncClock = func() time.Time { return time.Unix(1791244801, 0) }
	assertAsyncUnboundLegacy(t, c, a)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(asyncSettlementHeader) != "" {
			t.Error("malformed keyring negotiated admission")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": a})
	}))
	defer server.Close()
	c.baseURLs, c.httpc = []string{server.URL}, server.Client()
	if _, err := c.AuthorizeWithRoute(t.Context(), "key", &qtypes.OpenAIChatRequest{IdempotencyKey: "id", Model: a.Model}, "chat.completions"); err != nil {
		t.Fatal(err)
	}
}

func TestAsyncKeyringLogsOnce(t *testing.T) {
	if os.Getenv("PR_E_KEYRING_LOG_CHILD") == "1" {
		t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", `{"test":"missing-issuer"}`)
		for i := 0; i < 3; i++ {
			NewFromEnv()
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAsyncKeyringLogsOnce$") //nolint:gosec // Re-execute this test binary with a fixed selector, never configuration input.
	cmd.Env = append(os.Environ(), "PR_E_KEYRING_LOG_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v %s", err, output)
	}
	if strings.Count(string(output), `event="keyring_disabled"`) != 1 {
		t.Fatalf("not logged exactly once: %s", output)
	}
}

func TestAsyncDuplicateEnvelopeRecovery(t *testing.T) {
	for _, path := range []string{"async-v1", "sync"} {
		for _, variant := range []string{"missing_envelope", "null_envelope", "wrong_hash", "wrong_id", "wrong_url", "missing_cost", "pending", "wrong_version", "status_mismatch", "null_acceptance", "empty_acceptance"} {
			t.Run(path+"/"+variant, func(t *testing.T) {
				var reply map[string]any
				if err := json.Unmarshal(asyncFixture(t, "snapshot_sync_v1"), &reply); err != nil {
					t.Fatal(err)
				}
				data := reply["data"].(map[string]any)
				final := data["trusted_router_settlement"].(map[string]any)
				acceptance := data["acceptance"].(map[string]any)
				// Tempt the ordinary-result decoder to adopt an unvalidated amount.
				data["settled"], data["cost_microdollars"] = true, 999
				switch variant {
				case "missing_envelope":
					delete(data, "trusted_router_settlement")
				case "null_envelope":
					data["trusted_router_settlement"] = nil
				case "wrong_hash":
					acceptance["payload_hash"] = strings.Repeat("0", 64)
				case "wrong_id":
					final["settlement_id"] = "wrong"
				case "wrong_url":
					final["status_url"] = "/wrong"
				case "missing_cost":
					delete(final, "cost_microdollars")
				case "pending":
					final["settlement_status"], acceptance["settlement_status"] = "pending", "pending"
				case "wrong_version":
					final["v"] = 2
				case "status_mismatch":
					acceptance["settlement_status"] = "refunded"
				case "null_acceptance":
					data["acceptance"], data["trusted_router_settlement"] = nil, nil
				case "empty_acceptance":
					data["acceptance"], data["trusted_router_settlement"] = map[string]any{}, nil
				}
				var bodies [][]byte
				var modes []string
				a := fixtureAuthorization(t, true)
				c := bindFixture(t, a)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					raw, _ := io.ReadAll(r.Body)
					bodies, modes = append(bodies, raw), append(modes, r.Header.Get(asyncSettlementHeader))
					if a.async.accepted != nil {
						t.Error("invalid reply cached")
					}
					if r.Header.Get(asyncSettlementHeader) == "sync" && path == "async-v1" {
						_, _ = w.Write(asyncFixture(t, "snapshot_sync_v1"))
						return
					}
					_ = json.NewEncoder(w).Encode(reply)
				}))
				defer server.Close()
				c.baseURLs, c.httpc = []string{server.URL}, server.Client()
				a.pinControlPlaneEndpoint(0)
				if path == "sync" {
					c.asyncClock = func() time.Time { return time.Unix(1791245071, 0) }
				}
				result, err := c.Settle(t.Context(), a, fixtureUsage())
				if path == "async-v1" {
					if err != nil || result == nil || result.CostMicrodollars != 2 || a.async.accepted != result {
						t.Fatalf("recovery: %+v %v", result, err)
					}
					if strings.Join(modes, ",") != "async-v1,async-v1,async-v1,sync" {
						t.Fatal(modes)
					}
				} else {
					if err == nil || result != nil || a.async.accepted != nil || a.async.legacy {
						t.Fatalf("invalid reply adopted: %+v %v", result, err)
					}
					frozen := append([]byte(nil), a.async.frozen...)
					usage := fixtureUsage()
					usage.InputTokens++
					result, err = c.Settle(t.Context(), a, usage)
					if err == nil || result != nil || a.async.accepted != nil || !bytes.Equal(frozen, a.async.frozen) || strings.Join(modes, ",") != "sync,sync" {
						t.Fatalf("frozen recovery lost: %+v %v %v", result, err, modes)
					}
				}
				for _, raw := range bodies {
					if !bytes.Equal(raw, a.async.frozen) {
						t.Fatal("request bytes changed")
					}
				}
			})
		}
	}
}
