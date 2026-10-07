package trustedrouter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestAsyncTicketSignatureVerification(t *testing.T) {
	for _, name := range []string{"fixture", "zero_signature", "empty_keyring", "wrong_kid", "wrong_key", "padded_signature"} {
		t.Run(name, func(t *testing.T) {
			c, a := fixtureClient(), fixtureAuthorization(t, true)
			parts := strings.Split(a.SettlementTicket, ".")
			switch name {
			case "zero_signature":
				parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
			case "empty_keyring":
				c.asyncTicketKeys = nil
			case "wrong_kid":
				c.asyncTicketKeys["other"] = c.asyncTicketKeys["async-v1-fixture"]
				delete(c.asyncTicketKeys, "async-v1-fixture")
			case "wrong_key":
				c.asyncTicketKeys["async-v1-fixture"] = asyncTicketKey{public: make([]byte, 32), issuer: "router-fixture"}
			case "padded_signature":
				parts[2] += "=="
			}
			a.SettlementTicket = strings.Join(parts, ".")
			c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
			if c.AsyncSettlementNegotiated(a) != (name == "fixture") {
				t.Fatal("signature did not gate local behavior")
			}
			if name == "fixture" {
				return
			}
			if a.async != nil {
				t.Fatal("partial binding")
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(asyncSettlementHeader) != "" {
					t.Error("forged ticket activated settlement")
				}
				raw, _ := io.ReadAll(r.Body)
				if bytes.Contains(raw, []byte("billing_snapshot")) {
					t.Error("forgery changed body")
				}
				_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":19}}`)
			}))
			defer server.Close()
			c.baseURLs, c.httpc = []string{server.URL}, server.Client()
			a.pinControlPlaneEndpoint(0)
			if _, err := c.Settle(t.Context(), a, fixtureUsage()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAsyncTicketStrictJWS(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	public := private.Public().(ed25519.PublicKey)
	for _, name := range []string{"valid", "header_whitespace", "extra_header", "wrong_alg", "wrong_type", "duplicate_claim", "array_claims", "escaped_claim", "float_claim", "noncanonical_base64"} {
		t.Run(name, func(t *testing.T) {
			c, a := fixtureClient(), fixtureAuthorization(t, true)
			c.asyncTicketKeys = map[string]asyncTicketKey{"test": {public: public, issuer: "router-fixture"}}
			parts := strings.Split(a.SettlementTicket, ".")
			claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
			header := `{"alg":"EdDSA","kid":"test","typ":"tr-async-settle-v1"}`
			switch name {
			case "header_whitespace":
				header = `{ "alg":"EdDSA","kid":"test","typ":"tr-async-settle-v1"}`
			case "extra_header":
				header = `{"alg":"EdDSA","extra":"x","kid":"test","typ":"tr-async-settle-v1"}`
			case "wrong_alg":
				header = strings.ReplaceAll(header, "EdDSA", "HS256")
			case "wrong_type":
				header = strings.ReplaceAll(header, "tr-async-settle-v1", "other")
			case "duplicate_claim":
				claims = append([]byte(`{"exp":1791245100,`), claims[1:]...)
			case "array_claims":
				claims = []byte(`[]`)
			case "escaped_claim":
				claims = bytes.ReplaceAll(claims, []byte("router-settlement"), []byte(`router-\u0073ettlement`))
			case "float_claim":
				claims = append([]byte(`{"extra":1.5,`), claims[1:]...)
			}
			parts[0], parts[1] = base64.RawURLEncoding.EncodeToString([]byte(header)), base64.RawURLEncoding.EncodeToString(claims)
			if name == "noncanonical_base64" {
				parts[1] += "\n"
			}
			parts[2] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(parts[0]+"."+parts[1])))
			a.SettlementTicket = strings.Join(parts, ".")
			c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
			if c.AsyncSettlementNegotiated(a) != (name == "valid") {
				t.Fatal("strict wire rules bypassed", name)
			}
		})
	}
}

func captureAsyncLogs(t *testing.T, f func()) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	original := os.Stderr
	os.Stderr = file
	defer func() { os.Stderr = original }()
	f()
	raw, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestAsyncSnapshotSyncRecovery(t *testing.T) {
	for _, name := range []string{"finalized_fixture", "finalized_refunded", "ordinary_settle", "sync_mismatch", "legacy_5xx", "legacy_network", "sync_409", "sync_400", "sync_malformed", "sync_pending", "sync_missing_cost", "sync_retry"} {
		t.Run(name, func(t *testing.T) {
			var modes []string
			var frozen []byte
			syncCalls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mode := r.Header.Get(asyncSettlementHeader)
				modes = append(modes, mode)
				raw, _ := io.ReadAll(r.Body)
				if mode == "async-v1" {
					frozen = raw
					_, _ = io.WriteString(w, `{"data":{"acceptance":{"status":"sync_required"},"reason":"admission_stale"}}`)
					return
				}
				if mode == "" {
					_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":19}}`)
					return
				}
				if mode != "sync" || !bytes.Equal(raw, frozen) {
					t.Error("snapshot recovery changed body or mode")
				}
				syncCalls++
				switch name {
				case "finalized_refunded":
					raw := bytes.ReplaceAll(asyncFixture(t, "snapshot_sync_v1"), []byte(`"settled"`), []byte(`"refunded"`))
					raw = bytes.ReplaceAll(raw, []byte(`"cost_microdollars": 2`), []byte(`"cost_microdollars": 0`))
					_, _ = w.Write(raw)
					return
				case "legacy_5xx":
					w.WriteHeader(503)
					return
				case "legacy_network":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				case "sync_409":
					w.WriteHeader(409)
					return
				case "sync_400":
					w.WriteHeader(400)
					return
				case "sync_malformed":
					_, _ = io.WriteString(w, `{"data":`)
					return
				case "sync_pending":
					_, _ = w.Write(asyncFixture(t, "pending_v1"))
					return
				case "sync_missing_cost":
					_, _ = io.WriteString(w, `{"data":{"settled":true}}`)
					return
				case "sync_mismatch":
					_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":19}}`)
					return
				case "ordinary_settle":
					_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":2,"generation_id":"gen-v1"}}`)
					return
				case "sync_retry":
					if syncCalls == 1 {
						w.WriteHeader(503)
						return
					}
				}
				_, _ = w.Write(asyncFixture(t, "snapshot_sync_v1"))
			}))
			defer server.Close()
			a := fixtureAuthorization(t, true)
			c := bindFixture(t, a)
			c.baseURLs, c.httpc = []string{server.URL}, server.Client()
			a.pinControlPlaneEndpoint(0)
			var result *SettleResult
			var err error
			logs := captureAsyncLogs(t, func() { result, err = c.Settle(t.Context(), a, fixtureUsage()) })
			hard := strings.HasPrefix(name, "legacy_")
			refused := name == "sync_409" || name == "sync_400" || name == "sync_malformed" || name == "sync_pending" || name == "sync_missing_cost"
			if refused {
				if err == nil || result != nil || len(modes) != 2 {
					t.Fatalf("soft refusal entered legacy: %v %v", err, modes)
				}
				// A retry queue call keeps frozen bytes, even if its caller supplies changed usage.
				u := fixtureUsage()
				u.InputTokens = 100
				_, _ = c.Settle(t.Context(), a, u)
				if modes[len(modes)-1] != "sync" {
					t.Fatal("retry reentered async/legacy")
				}
				return
			}
			if name == "finalized_refunded" {
				if err != nil || result == nil || result.Settled || !result.AlreadySettled || result.FinalizationOutcome != "refunded" || !result.HasCost() || result.CostMicrodollars != 0 {
					t.Fatalf("refunded winner lost: %+v %v", result, err)
				}
				if !strings.Contains(logs, "expected_cost_microdollars=2 claimed_cost_microdollars=0") {
					t.Fatal("winner difference not logged", logs)
				}
				return
			}
			want := 2
			if hard || name == "sync_mismatch" {
				want = 19
			}
			if err != nil || result == nil || !result.Settled || result.CostMicrodollars != want || result.TrustedRouterSettlement != nil {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if hard {
				if syncCalls != 3 || modes[len(modes)-1] != "" || !strings.Contains(logs, `event="legacy_fallback"`) {
					t.Fatal(modes, logs)
				}
			} else if modes[len(modes)-1] != "sync" {
				t.Fatal("legacy used when snapshot sync available", modes)
			}
			if want == 19 && (!strings.Contains(logs, "expected_cost_microdollars=2") || !strings.Contains(logs, "claimed_cost_microdollars=19")) {
				t.Fatal("unlogged reprice", logs)
			}
		})
	}
}

func TestAsyncKeyringWiring(t *testing.T) {
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "on")
	t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", fixtureKeyring)
	for _, c := range []*Client{New("", "", nil), NewFromEnv(), NewFromBootstrap(nil)} {
		a := fixtureAuthorization(t, true)
		c.asyncClock = fixtureClient().asyncClock
		c.bindAsyncAuthorization(a, &qtypes.OpenAIChatRequest{}, "chat.completions")
		if !c.AsyncSettlementNegotiated(a) {
			t.Fatal("keyring not wired")
		}
	}
	boot := &qtypes.BootstrapData{AsyncSettleNegotiate: true, AsyncSettleTicketPublicKeys: fixtureKeyring}
	t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", "")
	if len(NewFromBootstrap(boot).asyncTicketKeys) != 0 {
		t.Fatal("empty environment did not override bootstrap")
	}
	if err := os.Unsetenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS"); err != nil {
		t.Fatal(err)
	}
	if len(NewFromBootstrap(boot).asyncTicketKeys) != 1 {
		t.Fatal("bootstrap keyring ignored")
	}
	for _, raw := range []string{"", `{}`, `null`, `[]`, `{"kid":"bad"}`} {
		t.Setenv("TR_ASYNC_SETTLE_TICKET_PUBLIC_KEYS", raw)
		if len(NewFromBootstrap(boot).asyncTicketKeys) != 0 {
			t.Fatal("invalid configuration activated", raw)
		}
	}
}

func TestAsyncSnapshotSyncFixturePin(t *testing.T) {
	raw := asyncFixture(t, "snapshot_sync_v1")
	const want = "rzl8IKlDxcg-UUy2SkA5eEL33JoXrFYvgiXbzlKAZ4E"
	if got := sha256.Sum256(raw); base64.RawURLEncoding.EncodeToString(got[:]) != want {
		t.Fatal("derived snapshot-sync fixture changed")
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
}

type asyncRoundTripper func(*http.Request) (*http.Response, error)

func (f asyncRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAsyncRecoveryAuthorityAndBudget(t *testing.T) {
	var deadlines []time.Time
	var modes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get(asyncSettlementHeader) {
		case "async-v1":
			_, _ = io.WriteString(w, `{"data":{"acceptance":{"status":"sync_required"}}}`)
		case "sync":
			w.WriteHeader(503)
		default:
			_, _ = io.WriteString(w, `{"data":{"settled":true,"cost_microdollars":2}}`)
		}
	}))
	defer server.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("billing authority changed"); w.WriteHeader(500) }))
	defer other.Close()
	a := fixtureAuthorization(t, true)
	c := bindFixture(t, a)
	c.baseURLs = []string{other.URL, server.URL}
	a.pinControlPlaneEndpoint(1)
	c.httpc = &http.Client{Transport: asyncRoundTripper(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Error("unbounded recovery")
		}
		deadlines = append(deadlines, deadline)
		modes = append(modes, r.Header.Get(asyncSettlementHeader))
		return http.DefaultTransport.RoundTrip(r)
	})}
	start := time.Now()
	if _, err := c.Settle(t.Context(), a, fixtureUsage()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(modes, ",") != "async-v1,sync,sync,sync," {
		t.Fatal(modes)
	}
	for _, d := range deadlines {
		if !d.Equal(deadlines[0]) || d.Sub(start) > settlementRetryBudget+time.Second {
			t.Fatal("recovery renewed budget", deadlines)
		}
	}
}
