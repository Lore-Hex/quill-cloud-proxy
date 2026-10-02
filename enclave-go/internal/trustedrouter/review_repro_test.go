package trustedrouter

import (
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
	"io"
	"net/http"
	"strings"
	"testing"
)

type reviewPanicObserver struct{ *testShadowObserver }

func (o *reviewPanicObserver) ObserveAuthorized(shadowobserve.Identity) {
	panic("shadow observer failed")
}
func TestReviewObserverPanicPreservesOrdinarySuccess(t *testing.T) {
	calls := 0
	c, _ := stageDTestClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"authorization_id":"auth","workspace_id":"w","api_key_hash":"k"}}`))}, nil
	})
	c.shadow = &reviewPanicObserver{newTestShadowObserver()}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("observer panic escaped after %d successful ordinary authorization: %v", calls, r)
		}
	}()
	a, _, err := c.authorizeAtDecodeSeam(t.Context(), strings.Repeat("a", 64), map[string]any{"idempotency_key": "one"}, spendlease.EstimateRequest{})
	if err != nil || a.AuthorizationID != "auth" {
		t.Fatal(a, err)
	}
}

type reviewVerdictObserver struct {
	*testShadowObserver
	statuses []int
}

func (o *reviewVerdictObserver) ObserveVerdict(_ string, status int, _, _ string) {
	o.statuses = append(o.statuses, status)
}
func TestReviewCancellationNotInfrastructureFailure(t *testing.T) {
	c, _ := stageDTestClient(t, func(req *http.Request) (*http.Response, error) { return nil, req.Context().Err() })
	observer := &reviewVerdictObserver{testShadowObserver: newTestShadowObserver()}
	c.shadow = observer
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err := c.authorizeAtDecodeSeam(ctx, strings.Repeat("a", 64), map[string]any{"idempotency_key": "one"}, spendlease.EstimateRequest{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if len(observer.statuses) != 0 {
		t.Fatalf("caller cancellation classified as authenticated infrastructure verdicts: %v", observer.statuses)
	}
}
func TestShadowBootOnlyHeaderParity(t *testing.T) {
	var headers []string
	c := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: stageDWireRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		headers = append(headers, req.Header.Get(spendlease.BootAuthHeader))
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"authorization_id":"auth"}}`))}, nil
	})})
	for mode := 0; mode < 2; mode++ {
		if mode == 1 {
			c.ConfigureShadowBoot(shadowSeedSigner(ed25519.NewKeyFromSeed(make([]byte, 32))))
			c.shadow = newTestShadowObserver()
		}
		if _, _, err := c.authorizeAtDecodeSeam(t.Context(), strings.Repeat("a", 64), map[string]any{"idempotency_key": "fixed"}, spendlease.EstimateRequest{}); err != nil {
			t.Fatal(err)
		}
	}
	if headers[0] != "" || headers[1] != "" {
		t.Fatal("unexpected setup", headers)
	}
	if c.shadowSigner == nil {
		t.Fatal("refresh signer missing")
	}
}

type panicEveryObserver struct {
	*testShadowObserver
	at string
}

func (o *panicEveryObserver) Excluded(s string) *shadowobserve.Execution {
	if o.at == "excluded" {
		panic("excluded")
	}
	return o.testShadowObserver.Excluded(s)
}
func (o *panicEveryObserver) ObserveVerdict(string, int, string, string) {
	if o.at == "verdict" {
		panic("verdict")
	}
}
func (o *panicEveryObserver) Suppressed(string)                          { panic("suppression") }
func (o *panicEveryObserver) Run(context.Context, shadowobserve.Refresh) { panic("worker") }
func TestEveryObserverCallbackIsIsolated(t *testing.T) {
	for _, at := range []string{"excluded", "verdict", "suppressed", "worker"} {
		t.Run(at, func(t *testing.T) {
			c, _ := stageDTestClient(t, func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 402, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":{"type":"insufficient_balance","message":"original"}}`))}, nil
			})
			c.shadow = &panicEveryObserver{newTestShadowObserver(), at}
			switch at {
			case "suppressed":
				c.ObserveShadowSuppressed("denial")
			case "worker":
				c.shadowCall(func() { c.shadow.Run(t.Context(), c.RefreshShadow) })
			default:
				_, _, err := c.authorizeAtDecodeSeam(t.Context(), strings.Repeat("a", 64), map[string]any{}, spendlease.EstimateRequest{})
				var cp *ControlPlaneError
				if !errors.As(err, &cp) || cp.StatusCode != 402 || cp.Message != "original" {
					t.Fatal("ordinary denial changed", err)
				}
			}
			if c.ShadowFailures() != 1 {
				t.Fatal("fault not counted", c.ShadowFailures())
			}
		})
	}
}

type scopeObserver struct {
	*testShadowObserver
	scope shadowobserve.Identity
}

func (o *scopeObserver) ObserveResolvedVerdict(_ string, _ int, _, _ string, id shadowobserve.Identity) {
	o.scope = id
}
func TestAuthenticatedErrorScopeCarriedToObserver(t *testing.T) {
	id := shadowobserve.Identity{KeyID: "k", WorkspaceID: "w", LookupDigest: strings.Repeat("a", 64)}
	c, _ := stageDTestClient(t, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 402, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":{"type":"insufficient_balance"},"data":{"workspace_id":"w","key_id":"k","lookup_digest":"` + id.LookupDigest + `"}}`))}, nil
	})
	observer := &scopeObserver{testShadowObserver: newTestShadowObserver()}
	c.shadow = observer
	_, _, err := c.authorizeAtDecodeSeam(t.Context(), id.LookupDigest, map[string]any{}, spendlease.EstimateRequest{})
	var cp *ControlPlaneError
	if !errors.As(err, &cp) || observer.scope != id {
		t.Fatal(err, observer.scope)
	}
}

func TestMalformedShadowScopePreservesOrdinaryError(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		c, _ := stageDTestClient(t, func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 402, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":{"type":"insufficient_balance","message":"original","reason":"billing_denied"},"data":{"workspace_id":42}}`))}, nil
		})
		if enabled {
			c.shadow = newTestShadowObserver()
		}
		_, _, err := c.authorizeAtDecodeSeam(t.Context(), strings.Repeat("a", 64), map[string]any{}, spendlease.EstimateRequest{})
		var cp *ControlPlaneError
		if !errors.As(err, &cp) || cp.Message != "original" || cp.Type != "insufficient_balance" || cp.Reason != "billing_denied" {
			t.Fatal("optional shadow metadata changed ordinary error", enabled, err)
		}
	}
}

func TestShadowInternalDeadlineClosesHealth(t *testing.T) {
	c := New("http://127.0.0.1:18080", "", nil)
	observer := &reviewVerdictObserver{testShadowObserver: newTestShadowObserver()}
	c.shadow = observer
	ctx, finish := c.observeShadowAuthorize(t.Context(), strings.Repeat("a", 64))
	retryCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, done := c.beginShadowAttempt(retryCtx, spendlease.AuthorizePath)
	done(context.DeadlineExceeded, true)
	if len(observer.statuses) != 1 || observer.statuses[0] != 503 {
		t.Fatal("internal timeout treated as caller cancellation", observer.statuses)
	}
	finish(nil, context.DeadlineExceeded)
	if len(observer.statuses) != 2 || observer.statuses[1] != 503 {
		t.Fatal("logical infrastructure failure missing", observer.statuses)
	}
}
