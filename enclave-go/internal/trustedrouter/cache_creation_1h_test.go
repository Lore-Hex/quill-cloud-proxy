package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/billingv1"
)

// goldenRequestSettleBody with three of its five cache-write tokens written
// for one hour. The only difference is the one new key.
const goldenOneHourSettleBody = `{"actual_input_tokens":120,"actual_output_tokens":34,"additional_cost_microdollars":77,"app":"my-app","app_categories":["coding"],"authorization_id":"auth_frozen","cache_affinity_explicit":true,"cache_affinity_key":"affinity-key","cache_creation_1h_input_tokens":3,"cache_creation_input_tokens":5,"cache_read_input_tokens":11,"client":{"attempt":1,"source":"tr","v":1},"elapsed_seconds":1.25,"finish_reason":"stop","first_token_seconds":0.4,"gateway_request_id":"rlog_00112233445566778899aabbccddeeff","http_referer":"https://example.test","metadata":{"k":"v"},"price_tier_input_tokens":100,"reasoning_tokens":9,"request_id":"chatcmpl_frozen","route_failures":["f1"],"route_fallbacks":1,"route_type":"chat.completions","selected_endpoint":"openai/gpt-4o-mini@openai/fallback","selected_model":"openai/gpt-4o-mini","service_tier":"flex","session_id":"session-1","status":"success","streamed":true,"trace":{"trace_id":"t-1"},"usage_estimated":false,"user":"user-1"}`

func TestSettleBodyCarriesOneHourCacheWritesOnlyWhenPositive(t *testing.T) {
	const key = `"cache_creation_1h_input_tokens":3,`
	if strings.Count(goldenOneHourSettleBody, key) != 1 || strings.Replace(goldenOneHourSettleBody, key, "", 1) != goldenRequestSettleBody {
		t.Fatal("one-hour golden differs from the settle golden by more than its key")
	}
	ctx := frozenTestContext(t.Context())
	for _, tc := range []struct {
		name  string
		count int
		want  string
	}{
		{"positive", 3, goldenOneHourSettleBody},
		{"zero", 0, goldenRequestSettleBody},
		{"negative", -3, goldenRequestSettleBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usage := frozenTestUsage()
			usage.CacheCreation1hInputTokens = tc.count
			body, err := buildSettleBody(ctx, frozenTestAuthorization(), usage)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != tc.want {
				t.Fatalf("settle body\n got: %s\nwant: %s", body, tc.want)
			}
			// A queued retry freezes the same bytes.
			c, _ := frozenTestGateway(t, nil)
			frozen, err := c.FreezeSettle(ctx, frozenTestAuthorization(), usage)
			if err != nil {
				t.Fatal(err)
			}
			if string(frozen.Body) != tc.want {
				t.Fatalf("frozen settle body\n got: %s\nwant: %s", frozen.Body, tc.want)
			}
			// And Settle sends them.
			c, captured := frozenTestGateway(t, nil)
			if _, err := c.Settle(ctx, frozenTestAuthorization(), usage); err != nil {
				t.Fatal(err)
			}
			got := captured()
			if len(got) != 1 || got[0].path != "/internal/gateway/settle" || got[0].body != tc.want {
				t.Fatalf("settle requests = %+v", got)
			}
		})
	}
}

// Every usage the billing contract prices asynchronously stops being an async
// settlement once it has a one-hour count: billing-v1 has no field for it.
func TestAsyncBuilderRefusesOneHourCacheWrites(t *testing.T) {
	count, withWrites := 0, 0
	for _, tc := range mergedBillingCases(t) {
		if tc.Charge == nil || len(tc.Snapshot) == 0 || len(tc.Raw) == 0 {
			continue
		}
		count++
		t.Run(tc.Name, func(t *testing.T) {
			a, u := bindBillingCase(t, tc)
			if _, err := buildAsyncSettlement(a.async, u); err != nil {
				t.Fatalf("without a one-hour count: %v", err)
			}
			counts := []int{1, -1}
			if u.CacheCreationInputTokens > 0 {
				withWrites++
				counts = append(counts, u.CacheCreationInputTokens)
			}
			for _, oneHour := range counts {
				u.CacheCreation1hInputTokens = oneHour
				body, err := buildAsyncSettlement(a.async, u)
				if !errors.Is(err, errCacheCreation1h) {
					t.Fatalf("one-hour count %d: err = %v", oneHour, err)
				}
				if body.Terminal != (billingv1.TerminalEnvelope{}) || body.Raw != (billingv1.RawUsage{}) || body.Ticket != "" || body.Snapshot != nil {
					t.Fatalf("one-hour count %d produced an async settlement: %+v", oneHour, body)
				}
			}
		})
	}
	if count < 30 || withWrites < 3 {
		t.Fatalf("only %d positive cases, %d with cache writes", count, withWrites)
	}
}

// End to end: the same authorization settles asynchronously without a
// one-hour count, and with one sends a single synchronous settle whose body
// carries the count.
func TestSettleWithOneHourCacheWritesIsSynchronous(t *testing.T) {
	for _, tc := range []struct {
		name      string
		oneHour   int
		wantAsync bool
	}{
		{"no one-hour count", 0, true},
		{"one-hour count", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := fixtureAuthorization(t, true)
			c := bindFixture(t, a)
			// One cache-write token in both cases; only the one-hour count differs.
			u := fixtureUsage()
			u.CacheCreationInputTokens, u.CacheCreation1hInputTokens = 1, tc.oneHour
			type request struct {
				mode, path string
				body       map[string]any
			}
			var mu sync.Mutex
			var requests []request
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				got := request{mode: r.Header.Get(asyncSettlementHeader), path: r.URL.Path}
				if err := json.Unmarshal(raw, &got.body); err != nil {
					t.Errorf("settle body: %v", err)
				}
				mu.Lock()
				requests = append(requests, got)
				mu.Unlock()
				if got.mode == "async-v1" {
					// Accept the terminal that was sent, as the router would.
					var sent asyncSettlementRequest
					var pending map[string]map[string]map[string]any
					if json.Unmarshal(raw, &sent) != nil || json.Unmarshal(asyncFixture(t, "pending_v1"), &pending) != nil {
						t.Error("async settle body or pending fixture did not decode")
					}
					hash, err := billingv1.CanonicalHash(sent.Terminal)
					if err != nil {
						t.Errorf("terminal hash: %v", err)
					}
					pending["data"]["acceptance"]["payload_hash"] = hash
					pending["data"]["trusted_router_settlement"]["cost_microdollars"] = sent.Terminal.ChargeMicro
					w.WriteHeader(http.StatusAccepted)
					_ = json.NewEncoder(w).Encode(pending)
					return
				}
				_, _ = io.WriteString(w, `{"data":{"cost_microdollars":7}}`)
			}))
			defer server.Close()
			c.baseURLs = []string{server.URL}
			c.httpc = server.Client()
			a.pinControlPlaneEndpoint(0)
			result, err := c.Settle(context.Background(), a, u)
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(requests) != 1 || requests[0].path != "/internal/gateway/settle" {
				t.Fatalf("requests = %+v", requests)
			}
			got := requests[0]
			if tc.wantAsync {
				rawUsage, _ := got.body["raw_usage"].(map[string]any)
				if got.mode != "async-v1" || got.body["terminal"] == nil || rawUsage["cache_creation_tokens"] != float64(1) {
					t.Fatalf("expected an async settlement: %+v", got)
				}
				if result.TrustedRouterSettlement == nil || !a.async.attempted || a.async.ineligible {
					t.Fatalf("result = %+v", result)
				}
				return
			}
			if got.mode != "" {
				t.Fatalf("settlement mode header = %q, want none", got.mode)
			}
			for _, asyncKey := range []string{"terminal", "raw_usage", "billing_snapshot", "settlement_ticket", "observed"} {
				if _, present := got.body[asyncKey]; present {
					t.Fatalf("synchronous settle carries async field %q: %+v", asyncKey, got.body)
				}
			}
			if got.body["cache_creation_1h_input_tokens"] != float64(tc.oneHour) || got.body["cache_creation_input_tokens"] != float64(1) || got.body["authorization_id"] != a.AuthorizationID {
				t.Fatalf("synchronous settle body = %+v", got.body)
			}
			if !a.async.ineligible || a.async.attempted || a.async.frozen != nil {
				t.Fatalf("async state = ineligible %v attempted %v frozen %s", a.async.ineligible, a.async.attempted, a.async.frozen)
			}
			if result.CostMicrodollars != 7 {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}
