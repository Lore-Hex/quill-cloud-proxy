package trustedrouter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestRerankWireGoldenAndNoAsync(t *testing.T) {
	if asyncCohort("rerank") || liveAsyncRoute("rerank") {
		t.Fatal("rerank must remain synchronous")
	}
	for _, mode := range []string{"off", "negotiate", "shadow", "both"} {
		t.Run(mode, func(t *testing.T) {
			var transcript []map[string]any
			httpc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				if r.Header.Get(asyncSettlementHeader) != "" || r.Header.Get(shadowPolicyHeader) != "" || r.Header.Get(shadowSettlementHeader) != "" {
					t.Error("rerank negotiated asynchronous settlement")
				}
				reply := `{"data":{"authorization_id":"auth-oracle","generation_id":"generation-oracle","invocation_nonce":"nonce-oracle","workspace_id":"workspace-oracle","model":"voyage/rerank-3","upstream_model":"rerank-3","provider":"voyage","endpoint_id":"endpoint-oracle","usage_type":"Credits","settlement_mode":"async","settlement_ticket":"opaque","async_eligible":true}}`
				if r.URL.Path == "/internal/gateway/settle" {
					reply = `{"data":{"generation_id":"generation-oracle","cost_microdollars":17,"cost":0.000017,"settled":true,"input_tokens":3,"output_tokens":0}}`
				} else if r.URL.Path != "/internal/gateway/authorize" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				transcript = append(transcript, map[string]any{"path": r.URL.Path, "headers": r.Header.Clone(), "body": string(body), "response": reply})
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(reply))}, nil
			})}
			c := New("https://trustedrouter.com", "oracle-token", httpc)
			c.asyncNegotiate = mode == "negotiate" || mode == "both"
			c.asyncShadow = mode == "shadow" || mode == "both"
			c.asyncTicketKeys = map[string]asyncTicketKey{"test": {}}
			invocation := &authorizationInvocation{nonce: "nonce-oracle"}
			invocation.once.Do(func() {})
			ctx := context.WithValue(t.Context(), authorizationInvocationContextKey{}, invocation)
			// A preexisting context value must not opt rerank into negotiation either.
			ctx = context.WithValue(ctx, asyncModeKey{}, "async-v1")
			a, err := c.AuthorizeEmbeddingsWithRouteSync(ctx, "test-key", &qtypes.EmbeddingRequest{Model: "voyage/rerank-3", IdempotencyKey: "oracle-idempotency"}, 3, "rerank")
			if err != nil {
				t.Fatal(err)
			}
			if c.AsyncSettlementNegotiated(a) {
				t.Fatal("rerank accepted asynchronous ticket")
			}
			result, err := c.Settle(ctx, a, Usage{RequestID: "request-oracle", InputTokens: 3, OutputTokens: 0, ElapsedSeconds: 1, RouteType: "rerank", SelectedEndpoint: "endpoint-oracle", SelectedModel: "voyage/rerank-3", Streamed: false})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(result)
			transcript = append(transcript, map[string]any{"settle_result": string(raw)})
			got, _ := json.MarshalIndent(transcript, "", "  ")
			const path = "testdata/async_off_main/rerank.json"
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("rerank wire changed\ngot %s\nwant %s", got, want)
			}
		})
	}
}
