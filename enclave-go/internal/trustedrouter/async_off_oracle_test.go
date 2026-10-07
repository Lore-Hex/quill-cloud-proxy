package trustedrouter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// This test also compiles on frozen main. Generate only on that disposable
// checkout, then compare this branch against those exact wire transcripts.
func TestAsyncOffFrozenMainTranscripts(t *testing.T) {
	t.Setenv("TR_ASYNC_SETTLE_NEGOTIATE", "off")
	for _, route := range []string{"chat.completions", "responses", "messages", "embeddings", "images", "videos", "decide"} {
		t.Run(route, func(t *testing.T) {
			var transcript []map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				headers := r.Header.Clone()
				headers.Del("Content-Length")
				reply := `{"data":{"authorization_id":"auth-oracle","generation_id":"generation-oracle","invocation_nonce":"nonce-oracle","workspace_id":"workspace-oracle","model":"test-model","provider":"openai","endpoint_id":"endpoint-oracle","usage_type":"Credits","additional_cost_reservation_microdollars":1,"settlement_mode":"async","billing_snapshot":{"future":true},"settlement_ticket":"opaque","async_eligible":true}}`
				if r.URL.Path != "/internal/gateway/authorize" {
					reply = `{"data":{"generation_id":"generation-oracle","cost_microdollars":17,"cost":0.000017,"trusted_router_settlement":{"v":1,"settlement_status":"pending","cost_microdollars":99},"settled":true,"input_tokens":3,"output_tokens":2}}`
				}
				transcript = append(transcript, map[string]any{"path": r.URL.Path, "headers": headers, "body": string(body), "response": reply})
				_, _ = io.WriteString(w, reply)
			}))
			defer server.Close()
			client := New(server.URL, "oracle-token", server.Client())
			invocation := &authorizationInvocation{nonce: "nonce-oracle"}
			invocation.once.Do(func() {})
			ctx := context.WithValue(t.Context(), authorizationInvocationContextKey{}, invocation)
			var auth *Authorization
			var err error
			if route == "embeddings" {
				auth, err = client.AuthorizeEmbeddings(ctx, "test-key", &qtypes.EmbeddingRequest{Model: "test-model", IdempotencyKey: "oracle-idempotency"}, 3)
			} else {
				auth, err = client.AuthorizeWithRoute(ctx, "test-key", &qtypes.OpenAIChatRequest{Model: "test-model", IdempotencyKey: "oracle-idempotency"}, route)
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Settle(ctx, auth, Usage{InputTokens: 3, OutputTokens: 2, RouteType: route, SelectedEndpoint: "endpoint-oracle", RequestID: "request-oracle", ElapsedSeconds: 1, CacheReadInputTokens: 1})
			if err != nil {
				t.Fatal(err)
			}
			resultBytes, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			transcript = append(transcript, map[string]any{"settle_result": string(resultBytes)})
			if err := client.Refund(ctx, auth, 502, "upstream_error", 1, nil); err != nil {
				t.Fatal(err)
			}
			refund, err := client.RefundDetailed(ctx, auth, 502, "upstream_error", 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			refundBytes, err := json.Marshal(refund)
			if err != nil {
				t.Fatal(err)
			}
			transcript = append(transcript, map[string]any{"refund_result": string(refundBytes)})
			if _, err := client.RefundDetailedAttributed(ctx, auth, 502, "upstream_error", 1, nil, RefundAttribution{User: "oracle-user", SessionID: "oracle-session"}); err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(transcript, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "async_off_main", route+".json")
			if os.Getenv("GENERATE_FROZEN_MAIN_ORACLE") == "1" {
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("flag-off differs from frozen main\ngot %s\nwant %s", got, want)
			}
		})
	}
}
