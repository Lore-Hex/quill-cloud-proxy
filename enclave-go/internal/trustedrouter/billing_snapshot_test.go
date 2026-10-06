package trustedrouter

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// Exercise the real authorize decoder with old and future routers. The optional
// fields are passive metadata; unknown pricing versions must not invoke v1
// validation or interfere with the existing synchronous authorization path.
func TestAuthorizeOptionalSettlementMetadata(t *testing.T) {
	for _, tc := range []struct{ name, extra, mode string }{
		{"absent", "", ""},
		{"generation_only", `,"generation_id":"gen-1"`, ""},
		{"sync", `,"generation_id":"gen-1","settlement_mode":"sync"`, "sync"},
		{"async_metadata", `,"generation_id":"gen-1","settlement_mode":"async","billing_snapshot":{"v":999,"future":true},"settlement_ticket":"ticket-1","settlement_status_url":"/v1/settlements/gen-1"`, "async"},
		{"unknown_capability", `,"generation_id":"gen-1","settlement_mode":"future-mode","billing_snapshot":{"v":999,"future":true},"settlement_ticket":"ticket-1","settlement_status_url":"/v1/settlements/gen-1"`, "future-mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"data":{"authorization_id":"auth-1","workspace_id":"ws-1","api_key_hash":"key-1","model":"openai/test","endpoint_id":"endpoint-1","provider":"openai","usage_type":"Credits","limit_usage_type":"Credits","route_candidates":[]` + tc.extra + `}}`
			calls := 0
			var settlePayload map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					_, _ = io.WriteString(w, body)
				case "/internal/gateway/settle":
					if err := json.NewDecoder(r.Body).Decode(&settlePayload); err != nil {
						t.Error(err)
					}
					_, _ = io.WriteString(w, `{"data":{"generation_id":"gen-final","settled":true,"disposition":"finalized","cost_microdollars":13}}`)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
				}
			}))
			defer server.Close()
			client := New(server.URL, "internal", server.Client())
			auth, err := client.Authorize(t.Context(), "sk-test", &qtypes.OpenAIChatRequest{Model: "openai/test"})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || auth.AuthorizationID != "auth-1" || auth.SettlementMode != tc.mode {
				t.Fatalf("unexpected authorization: %+v calls=%d", auth, calls)
			}
			if tc.name != "absent" && auth.GenerationID != "gen-1" {
				t.Fatal("generation ID lost")
			}
			if tc.name == "async_metadata" || tc.name == "unknown_capability" {
				if string(auth.BillingSnapshot) != `{"v":999,"future":true}` || auth.SettlementTicket != "ticket-1" || auth.SettlementStatusURL != "/v1/settlements/gen-1" {
					t.Fatal("optional metadata lost")
				}
			} else if auth.BillingSnapshot != nil || auth.SettlementTicket != "" || auth.SettlementStatusURL != "" {
				t.Fatal("absent fields not optional")
			}
			settled, err := client.Settle(t.Context(), auth, Usage{InputTokens: 10, OutputTokens: 3})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 2 || !settled.Settled || settled.CostMicrodollars != 13 || settled.GenerationID != "gen-final" {
				t.Fatalf("synchronous settle changed: %+v calls=%d", settled, calls)
			}
			for _, key := range []string{"generation_id", "settlement_mode", "billing_snapshot", "settlement_ticket", "settlement_status_url"} {
				if _, exists := settlePayload[key]; exists {
					t.Fatalf("passive metadata entered settle: %s", key)
				}
			}
			// Strip only newly parsed metadata and compare every preexisting wire field.
			auth.GenerationID = ""
			auth.SettlementMode = ""
			auth.BillingSnapshot = nil
			auth.SettlementTicket = ""
			auth.SettlementStatusURL = ""
			got, err := json.Marshal(auth)
			if err != nil {
				t.Fatal(err)
			}
			var original struct {
				Data Authorization `json:"data"`
			}
			if err = json.Unmarshal([]byte(body), &original); err != nil {
				t.Fatal(err)
			}
			original.Data.GenerationID = ""
			original.Data.SettlementMode = ""
			original.Data.BillingSnapshot = nil
			original.Data.SettlementTicket = ""
			original.Data.SettlementStatusURL = ""
			want, err := json.Marshal(original.Data)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("existing fields changed: %s vs %s", got, want)
			}
		})
	}
}
