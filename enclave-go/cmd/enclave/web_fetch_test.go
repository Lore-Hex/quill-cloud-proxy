package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/webfetch"
)

type fakeFetch struct {
	calls    int
	scenario string
	cancel   context.CancelFunc
}

func (f *fakeFetch) Fetch(_ context.Context, r *webfetch.Request) (*webfetch.Result, error) {
	f.calls++
	if f.scenario == "failure" {
		return nil, &webfetch.ProviderError{Status: 429}
	}
	if f.scenario == "empty" {
		return &webfetch.Result{Content: " "}, nil
	}
	if f.scenario == "cancel-after-success" {
		f.cancel()
	}
	return &webfetch.Result{Title: "Private title", Content: "Private fetched content"}, nil
}

func TestWebFetchLifecycle(t *testing.T) {
	for _, scenario := range []string{"success", "failure", "empty", "denied", "replay", "missing-fee", "wrong-provider", "byok", "settle-failure", "cancel-after-success"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			var auth, settle map[string]any
			var calls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				calls = append(calls, r.URL.Path)
				body, _ := io.ReadAll(r.Body)
				for _, secret := range []string{"example.com", "private-query", "Private fetched", "Private title", "tr-test-key"} {
					if bytes.Contains(body, []byte(secret)) {
						t.Errorf("content leaked to control plane: %s", secret)
					}
				}
				var decoded map[string]any
				json.Unmarshal(body, &decoded)
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/internal/gateway/authorize":
					auth = decoded
					if scenario == "denied" {
						w.WriteHeader(402)
						io.WriteString(w, `{"error":{"message":"insufficient credits"}}`)
						return
					}
					provider, usage, fee := "deepseek", "Credits", 792
					if scenario == "missing-fee" {
						fee = 0
					}
					if scenario == "wrong-provider" {
						provider = "openai"
					}
					if scenario == "byok" {
						usage = "BYOK"
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
						"authorization_id": "auth_fetch", "model": webfetch.ModelID,
						"provider": provider, "upstream_model": "fetch", "usage_type": usage,
						"endpoint_id": "deepseek/fetch@deepseek/prepaid", "estimated_cost_microdollars": fee,
						"idempotent_replay": scenario == "replay",
					}})
				case "/internal/gateway/settle":
					settle = decoded
					if scenario == "settle-failure" {
						w.WriteHeader(400)
						io.WriteString(w, `{"error":{"message":"bad settlement"}}`)
						return
					}
					io.WriteString(w, `{"data":{"generation_id":"gen_fetch","cost_microdollars":792,"cost":0.000792,"settled":true}}`)
				case "/internal/gateway/refund":
					io.WriteString(w, `{"data":{"settled":true}}`)
				default:
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fetcher := &fakeFetch{scenario: scenario, cancel: cancel}
			old := webFetchProviderGateway
			webFetchProviderGateway = fetcher
			t.Cleanup(func() { webFetchProviderGateway = old })
			var out bytes.Buffer
			serveWebFetch(ctx, &out, []byte(`{"url":"https://example.com/?private-query=secret"}`), trustedrouter.New(server.URL, "internal", server.Client()), "tr-test-key", "fetch-one", requestAttributionHeaders{}, "rlog_fetch")
			mu.Lock()
			defer mu.Unlock()
			if auth["route_type"] != "tools.fetch" || auth["estimated_input_tokens"] != float64(0) || auth["max_output_tokens"] != float64(1) || len(auth["request_fingerprint"].(string)) != 64 {
				t.Fatalf("wrong authorization: %v", auth)
			}
			wantFetch := 1
			if scenario == "denied" || scenario == "replay" || scenario == "missing-fee" || scenario == "wrong-provider" || scenario == "byok" {
				wantFetch = 0
			}
			if fetcher.calls != wantFetch {
				t.Fatalf("unexpected upstream calls: %d", fetcher.calls)
			}
			wantSettle := scenario == "success" || scenario == "settle-failure" || scenario == "cancel-after-success"
			if (settle != nil) != wantSettle {
				t.Fatalf("unexpected settlement: %v", settle)
			}
			if settle != nil && (settle["actual_input_tokens"] != float64(0) || settle["actual_output_tokens"] != float64(0) || settle["route_type"] != "tools.fetch") {
				t.Fatalf("wrong usage: %v", settle)
			}
			refunds := 0
			for _, path := range calls {
				if strings.HasSuffix(path, "/refund") {
					refunds++
				}
			}
			wantRefund := 0
			if scenario == "failure" || scenario == "empty" || scenario == "missing-fee" || scenario == "wrong-provider" || scenario == "byok" {
				wantRefund = 1
			}
			if refunds != wantRefund {
				t.Fatalf("unexpected refunds %d, want %d", refunds, wantRefund)
			}
			if scenario == "success" || scenario == "cancel-after-success" {
				if !strings.HasPrefix(out.String(), "HTTP/1.1 200") || !strings.Contains(out.String(), "X-Usage-Cost: 0.000792") || !strings.Contains(out.String(), "Private fetched content") {
					t.Fatalf("bad response: %s", out.String())
				}
			} else if strings.Contains(out.String(), "Private fetched content") {
				t.Fatal("delivered unpaid content")
			}
		})
	}
}
