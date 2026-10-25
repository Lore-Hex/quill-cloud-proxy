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

// The split-out builders return exactly the bytes Settle and Refund sent
// before the split.
func TestBuildSettleAndRefundBodiesMatchRequestGolden(t *testing.T) {
	ctx := frozenTestContext(t.Context())
	settle, err := buildSettleBody(ctx, frozenTestAuthorization(), frozenTestUsage())
	if err != nil || string(settle) != goldenRequestSettleBody {
		t.Fatalf("buildSettleBody err=%v\n got: %s\nwant: %s", err, settle, goldenRequestSettleBody)
	}
	refund, err := buildRefundBody(ctx, frozenTestAuthorization(), 503, "upstream_timeout", 2.5,
		map[string]any{"reason": "fixture"},
		RefundAttribution{User: "user-1", SessionID: "session-1", Trace: map[string]any{"trace_id": "t-1"}})
	if err != nil || string(refund) != goldenRequestRefundBody {
		t.Fatalf("buildRefundBody err=%v\n got: %s\nwant: %s", err, refund, goldenRequestRefundBody)
	}
}

// retryCompactedAuthorization mirrors the settlement retry queue's
// compaction (cmd/enclave compactSettlementRetryJob): only the billing
// identity and the pinned authority survive.
func retryCompactedAuthorization(auth *Authorization) *Authorization {
	return &Authorization{
		AuthorizationID: auth.AuthorizationID, Model: auth.Model, EndpointID: auth.EndpointID,
		RouteType: auth.RouteType, ControlPlaneEndpoint: auth.ControlPlaneEndpoint,
		ControlPlaneEndpointSet: auth.ControlPlaneEndpointSet,
	}
}

// Freezing and posting sends the same bytes, to the same authority, as the
// legacy Settle and RefundDetailed the retry queue used to call.
func TestPostFrozenTerminalSendsLegacyRetryBytes(t *testing.T) {
	c, captured := frozenTestGateway(t, nil)
	ctx := frozenTestContext(t.Context())
	auth := retryCompactedAuthorization(frozenTestAuthorization())
	usage := frozenTestUsage()
	usage.User, usage.SessionID, usage.Trace, usage.Metadata = "", "", nil, nil
	usage.App, usage.HTTPReferer, usage.AppCategories = "", "", nil
	if _, err := c.Settle(ctx, auth, usage); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RefundDetailed(ctx, auth, 0, "", 0, nil); err != nil {
		t.Fatal(err)
	}
	settle, err := c.FreezeSettle(ctx, auth, usage)
	if err != nil {
		t.Fatal(err)
	}
	refund, err := c.FreezeRefund(ctx, auth, 0, "", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if settle.Path != "/internal/gateway/settle" || refund.Path != "/internal/gateway/refund" ||
		settle.BaseURL != c.baseURLs[1] || refund.BaseURL != c.baseURLs[1] || settle.BootAuth != "" || refund.BootAuth != "" {
		t.Fatalf("frozen settle=%+v refund=%+v", settle, refund)
	}
	// The frozen request is self-contained: a bare context sends the same bytes.
	for _, frozen := range []*FrozenTerminal{settle, refund} {
		if _, err := c.PostFrozenTerminal(context.Background(), *frozen); err != nil {
			t.Fatal(err)
		}
	}
	got := captured()
	if len(got) != 4 {
		t.Fatalf("requests = %d, want 4", len(got))
	}
	for i := range 2 {
		legacy, frozen := got[i], got[i+2]
		if legacy.path != frozen.path || legacy.endpoint != frozen.endpoint || legacy.body != frozen.body {
			t.Fatalf("frozen %s to %d differs from legacy %s to %d\n got: %s\nwant: %s",
				frozen.path, frozen.endpoint, legacy.path, legacy.endpoint, frozen.body, legacy.body)
		}
	}
	if string(settle.Body) != got[0].body || string(refund.Body) != got[1].body {
		t.Fatal("frozen bodies differ from the bytes sent")
	}
}

func TestFreezeTerminalAuthority(t *testing.T) {
	c, _ := frozenTestGateway(t, nil)
	single := New(c.baseURLs[0], "internal-test", &http.Client{})
	unpinned := retryCompactedAuthorization(frozenTestAuthorization())
	unpinned.ControlPlaneEndpoint, unpinned.ControlPlaneEndpointSet = 0, false
	for _, tc := range []struct {
		name          string
		client        *Client
		auth          *Authorization
		settle, refnd string
	}{
		{"pinned", c, frozenTestAuthorization(), c.baseURLs[1], c.baseURLs[1]},
		// An unpinned settle and refund go to the first dialable authority.
		{"unpinned", c, unpinned, "", ""},
		// A settle with one authority pins it (postSettlementJSON); a refund does not.
		{"single", single, unpinned, c.baseURLs[0], ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settle, err := tc.client.FreezeSettle(t.Context(), tc.auth, frozenTestUsage())
			if err != nil || settle.BaseURL != tc.settle {
				t.Fatalf("settle authority %q err=%v, want %q", settle.BaseURL, err, tc.settle)
			}
			refund, err := tc.client.FreezeRefund(t.Context(), tc.auth, 502, "", 1, nil)
			if err != nil || refund.BaseURL != tc.refnd {
				t.Fatalf("refund authority %q err=%v, want %q", refund.BaseURL, err, tc.refnd)
			}
		})
	}
	// An index the client cannot resolve fails with the error Settle returns.
	invalid := frozenTestAuthorization()
	invalid.pinControlPlaneEndpoint(5)
	_, settleErr := c.Settle(t.Context(), invalid, frozenTestUsage())
	_, freezeErr := c.FreezeSettle(t.Context(), invalid, frozenTestUsage())
	if settleErr == nil || freezeErr == nil || settleErr.Error() != freezeErr.Error() {
		t.Fatalf("settle err=%v freeze err=%v", settleErr, freezeErr)
	}
	// A refund without an authorization has nothing to send.
	if frozen, err := c.FreezeRefund(t.Context(), nil, 502, "", 1, nil); frozen != nil || err != nil {
		t.Fatalf("nil authorization froze %+v err=%v", frozen, err)
	}
	if _, err := c.PostFrozenTerminal(t.Context(), FrozenTerminal{Path: "/internal/gateway/authorize", Body: []byte(`{}`)}); err == nil {
		t.Fatal("posted a frozen request that is not a settle or refund")
	}
	if _, err := c.PostFrozenTerminal(t.Context(), FrozenTerminal{Path: "/internal/gateway/settle", Body: []byte(`{}`), BaseURL: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("posted to an authority the client does not have")
	}
}

// A frozen settle keeps postSettlementJSON's pinned retry policy: three
// transport tries at the pinned authority for 5xx, one try otherwise.
func TestPostFrozenSettleUsesPinnedRetryPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		auth      func(*Authorization)
		status    func(int) int
		wantCalls int
		wantErr   bool
	}{
		{"recovers_on_third", nil, func(n int) int {
			if n < 3 {
				return http.StatusBadGateway
			}
			return http.StatusOK
		}, 3, false},
		{"gives_up_after_three", nil, func(int) int { return http.StatusServiceUnavailable }, 3, true},
		{"rejection_is_final", nil, func(int) int { return http.StatusBadRequest }, 1, true},
		{"unpinned_sends_once", func(a *Authorization) { a.ControlPlaneEndpointSet = false }, func(int) int { return http.StatusBadGateway }, 1, true},
		{"unnamed_sends_once", func(a *Authorization) { a.AuthorizationID = "" }, func(int) int { return http.StatusBadGateway }, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, captured := frozenTestGateway(t, tc.status)
			auth := retryCompactedAuthorization(frozenTestAuthorization())
			if tc.auth != nil {
				tc.auth(auth)
			}
			frozen, err := c.FreezeSettle(t.Context(), auth, frozenTestUsage())
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.PostFrozenTerminal(t.Context(), *frozen)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, want error %t", err, tc.wantErr)
			}
			got := captured()
			if len(got) != tc.wantCalls {
				t.Fatalf("attempts = %d, want %d", len(got), tc.wantCalls)
			}
			for _, attempt := range got {
				if attempt.body != string(frozen.Body) || attempt.endpoint != got[0].endpoint {
					t.Fatal("a retry changed its bytes or authority")
				}
			}
		})
	}
}

// A frozen refund is sent once, even on 5xx, and leaves even when the caller's
// context is already cancelled, as RefundDetailed does.
func TestPostFrozenRefundSendsOnceDespiteCancellation(t *testing.T) {
	c, captured := frozenTestGateway(t, func(int) int { return http.StatusBadGateway })
	frozen, err := c.FreezeRefund(t.Context(), frozenTestAuthorization(), 502, "", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.PostFrozenTerminal(cancelled, *frozen); err == nil {
		t.Fatal("5xx refund reported success")
	}
	if got := captured(); len(got) != 1 || got[0].endpoint != 1 || got[0].body != string(frozen.Body) {
		t.Fatalf("refund attempts = %d, want one at the pinned authority", len(got))
	}
}

// Compaction drops the authorization's async and shadow state, so a retry
// never sent those headers. A frozen replay never sends them either, even on a
// context that still carries them.
func TestPostFrozenTerminalDropsAsyncAndShadowHeaders(t *testing.T) {
	setShadowRevision(t)
	c, auth := shadowAuth(t)
	server, captured := frozenTestGateway(t, nil)
	c.baseURLs, c.httpc, c.internalToken = server.baseURLs, server.httpc, server.internalToken
	auth.pinControlPlaneEndpoint(1)
	usage := shadowUsage()
	ctx := frozenTestContext(t.Context())

	// Positive controls: the request path sends the shadow header, and a
	// context carrying an async mode would send it on an ordinary post.
	if _, err := c.Settle(ctx, auth, usage); err != nil {
		t.Fatal(err)
	}
	leftover := context.WithValue(context.WithValue(ctx, asyncModeKey{}, "sync"), shadowHeaderKey{}, "")
	if err := c.postSettlement(leftover, 1, auth.AuthorizationID, []byte(`{}`), "", nil); err != nil {
		t.Fatal(err)
	}
	compacted := retryCompactedAuthorization(auth)
	// Today's retry: Settle on the compacted authorization.
	if _, err := c.Settle(ctx, compacted, usage); err != nil {
		t.Fatal(err)
	}
	frozen, err := c.FreezeSettle(ctx, compacted, usage)
	if err != nil {
		t.Fatal(err)
	}
	inherited := context.WithValue(context.WithValue(ctx, asyncModeKey{}, "sync"), shadowHeaderKey{}, "inherited-shadow")
	if _, err := c.PostFrozenTerminal(inherited, *frozen); err != nil {
		t.Fatal(err)
	}
	refund, err := c.FreezeRefund(ctx, compacted, 502, "", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PostFrozenTerminal(inherited, *refund); err != nil {
		t.Fatal(err)
	}
	got := captured()
	if len(got) != 5 {
		t.Fatalf("requests = %d, want 5", len(got))
	}
	if got[0].header.Get(shadowSettlementHeader) == "" || got[1].header.Get(asyncSettlementHeader) != "sync" {
		t.Fatal("positive controls did not send the async or shadow header")
	}
	for i, sent := range got[2:] {
		for _, header := range []string{asyncSettlementHeader, shadowSettlementHeader, shadowPolicyHeader, "X-TR-Boot-Auth"} {
			if sent.header.Get(header) != "" {
				t.Fatalf("replay %d sent %s", i, header)
			}
		}
	}
	if got[3].body != got[2].body || got[3].endpoint != got[2].endpoint {
		t.Fatal("frozen settle differs from today's compacted retry")
	}
}
