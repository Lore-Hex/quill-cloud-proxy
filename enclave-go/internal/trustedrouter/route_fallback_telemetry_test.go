package trustedrouter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSettleSendsBoundedFallbackMetadataOnlyWhenUsed(t *testing.T) {
	for _, count := range []int{0, 10} {
		t.Run(string(rune('a'+count)), func(t *testing.T) {
			var body map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				_, _ = w.Write([]byte(`{"data":{"cost_microdollars":1}}`))
			}))
			defer server.Close()
			failures := make([]string, 10)
			for i := range failures {
				failures[i] = "provider|endpoint|upstream_5xx"
			}
			_, err := New(server.URL, "test", server.Client()).Settle(t.Context(), &Authorization{AuthorizationID: "a"}, Usage{RouteFallbacks: count, RouteFailures: failures})
			if err != nil {
				t.Fatal(err)
			}
			if count == 0 {
				if body["route_fallbacks"] != nil || body["route_failures"] != nil {
					t.Fatalf("unexpected fallback metadata: %v", body)
				}
			} else if body["route_fallbacks"] != float64(count) || len(body["route_failures"].([]any)) != 8 {
				t.Fatalf("incorrect fallback metadata: %v", body)
			}
		})
	}
}
