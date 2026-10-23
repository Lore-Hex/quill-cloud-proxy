package trustedrouter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const frozenTestRequestLogID = "rlog_00112233445566778899aabbccddeeff"

type frozenTestCapture struct {
	endpoint int
	path     string
	body     string
	header   http.Header
}

// frozenTestGateway is a two-authority control plane that records each
// request and answers every one with status (200 unless set).
func frozenTestGateway(t *testing.T, status func(attempt int) int) (*Client, func() []frozenTestCapture) {
	t.Helper()
	var mu sync.Mutex
	var captured []frozenTestCapture
	handler := func(endpoint int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read body: %v", err)
			}
			mu.Lock()
			captured = append(captured, frozenTestCapture{endpoint: endpoint, path: r.URL.Path, body: string(raw), header: r.Header.Clone()})
			attempt := len(captured)
			mu.Unlock()
			if status != nil {
				if code := status(attempt); code != http.StatusOK {
					http.Error(w, `{"error":{"message":"fixture"}}`, code)
					return
				}
			}
			_, _ = io.WriteString(w, `{"data":{"cost_microdollars":15,"disposition":"finalized"}}`)
		})
	}
	primary := httptest.NewServer(handler(0))
	t.Cleanup(primary.Close)
	secondary := httptest.NewServer(handler(1))
	t.Cleanup(secondary.Close)
	c := New(primary.URL+","+secondary.URL, "internal-test", &http.Client{})
	if err := c.ConfigurationError(); err != nil {
		t.Fatal(err)
	}
	return c, func() []frozenTestCapture {
		mu.Lock()
		defer mu.Unlock()
		return append([]frozenTestCapture(nil), captured...)
	}
}

func frozenTestAuthorization() *Authorization {
	auth := &Authorization{
		AuthorizationID: "auth_frozen", Model: "openai/gpt-4o-mini",
		EndpointID: "openai/gpt-4o-mini@openai/prepaid", RouteType: "chat.completions",
		WorkspaceID: "workspace-private", APIKeyHash: "key-hash-private",
	}
	auth.cacheAffinityKey = "affinity-key"
	auth.cacheAffinityExplicit = true
	auth.pinControlPlaneEndpoint(1)
	return auth
}

func frozenTestUsage() Usage {
	return Usage{
		RequestID: "chatcmpl_frozen", InputTokens: 120, OutputTokens: 34, ElapsedSeconds: 1.25,
		FirstTokenSeconds: 0.4, ReasoningTokens: 9, PriceTierInputTokens: 100,
		Streamed: true, RouteType: "chat.completions",
		SelectedEndpoint: "openai/gpt-4o-mini@openai/fallback", RouteFallbacks: 1, RouteFailures: []string{"f1"},
		User: "user-1", SessionID: "session-1", Trace: map[string]any{"trace_id": "t-1"},
		Metadata: map[string]any{"k": "v"}, App: "my-app", HTTPReferer: "https://example.test",
		AppCategories: []string{"coding"}, CacheReadInputTokens: 11, CacheCreationInputTokens: 5,
		AdditionalCostMicrodollars: 77, ServiceTier: "flex",
	}
}

func frozenTestContext(ctx context.Context) context.Context {
	ctx = WithRequestLogID(ctx, frozenTestRequestLogID)
	return WithClientContext(ctx, &qtypes.ClientContext{V: 1, Source: "tr", Attempt: intPtrFrozenTest(1)})
}

func intPtrFrozenTest(value int) *int { return &value }

// Captured from Settle and RefundDetailedAttributed on the commit before
// settle and refund bodies were split out of them.
const (
	goldenRequestSettleBody = `{"actual_input_tokens":120,"actual_output_tokens":34,"additional_cost_microdollars":77,"app":"my-app","app_categories":["coding"],"authorization_id":"auth_frozen","cache_affinity_explicit":true,"cache_affinity_key":"affinity-key","cache_creation_input_tokens":5,"cache_read_input_tokens":11,"client":{"attempt":1,"source":"tr","v":1},"elapsed_seconds":1.25,"finish_reason":"stop","first_token_seconds":0.4,"gateway_request_id":"rlog_00112233445566778899aabbccddeeff","http_referer":"https://example.test","metadata":{"k":"v"},"price_tier_input_tokens":100,"reasoning_tokens":9,"request_id":"chatcmpl_frozen","route_failures":["f1"],"route_fallbacks":1,"route_type":"chat.completions","selected_endpoint":"openai/gpt-4o-mini@openai/fallback","selected_model":"openai/gpt-4o-mini","service_tier":"flex","session_id":"session-1","status":"success","streamed":true,"trace":{"trace_id":"t-1"},"usage_estimated":false,"user":"user-1"}`
	goldenRequestRefundBody = `{"app":"attested-gateway","authorization_id":"auth_frozen","client":{"attempt":1,"source":"tr","v":1},"elapsed_seconds":2.5,"error_status":503,"error_type":"upstream_timeout","gateway_request_id":"rlog_00112233445566778899aabbccddeeff","metadata":{"reason":"fixture"},"route_type":"chat.completions","selected_endpoint":"openai/gpt-4o-mini@openai/prepaid","selected_model":"openai/gpt-4o-mini","session_id":"session-1","streamed":true,"trace":{"trace_id":"t-1"},"user":"user-1"}`
)

func TestSettleAndRefundRequestBytesMatchGolden(t *testing.T) {
	c, captured := frozenTestGateway(t, nil)
	ctx := frozenTestContext(t.Context())
	if _, err := c.Settle(ctx, frozenTestAuthorization(), frozenTestUsage()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RefundDetailedAttributed(ctx, frozenTestAuthorization(), 503, "upstream_timeout", 2.5,
		map[string]any{"reason": "fixture"},
		RefundAttribution{User: "user-1", SessionID: "session-1", Trace: map[string]any{"trace_id": "t-1"}}); err != nil {
		t.Fatal(err)
	}
	got := captured()
	if len(got) != 2 {
		t.Fatalf("requests = %d, want 2", len(got))
	}
	for i, want := range []struct{ path, body string }{
		{"/internal/gateway/settle", goldenRequestSettleBody},
		{"/internal/gateway/refund", goldenRequestRefundBody},
	} {
		if got[i].path != want.path || got[i].endpoint != 1 {
			t.Fatalf("request %d went to %s at authority %d", i, got[i].path, got[i].endpoint)
		}
		if got[i].body != want.body {
			t.Errorf("request %d body changed\n got: %s\nwant: %s", i, got[i].body, want.body)
		}
	}
}
