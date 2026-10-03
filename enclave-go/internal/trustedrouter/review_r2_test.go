package trustedrouter

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
)

func TestReviewR2AllOrdinaryHeadersParity(t *testing.T) {
	for _, signed := range []bool{false, true} {
		t.Run(map[bool]string{false: "stageD-off", true: "stageD-on"}[signed], func(t *testing.T) {
			var headers []http.Header
			var bodies []string
			c := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: stageDWireRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				headers = append(headers, req.Header.Clone())
				b, _ := io.ReadAll(req.Body)
				bodies = append(bodies, string(b))
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"authorization_id":"auth"}}`))}, nil
			})})
			signer := shadowSeedSigner(ed25519.NewKeyFromSeed(make([]byte, 32)))
			if signed {
				c.stageDBootSigner = signer
			}
			for mode := 0; mode < 2; mode++ {
				if mode == 1 {
					c.ConfigureShadowBoot(signer)
					c.shadow = newTestShadowObserver()
				}
				inv := &authorizationInvocation{nonce: "fixed-nonce"}
				inv.once.Do(func() {})
				ctx := context.WithValue(t.Context(), authorizationInvocationContextKey{}, inv)
				_, _, err := c.authorizeAtDecodeSeam(ctx, strings.Repeat("a", 64), map[string]any{"idempotency_key": "fixed-key"}, spendlease.EstimateRequest{})
				if err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(headers[0], headers[1]) || bodies[0] != bodies[1] {
				t.Fatal(headers, bodies)
			}
			t.Logf("identical headers: %v", headers[0])
		})
	}
}
func TestReviewR2CallbackPanicPreservesCallerCancellation(t *testing.T) {
	c, _ := stageDTestClient(t, func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })
	c.shadow = &panicEveryObserver{newTestShadowObserver(), "excluded"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err := c.authorizeAtDecodeSeam(ctx, strings.Repeat("a", 64), map[string]any{}, spendlease.EstimateRequest{})
	if !errors.Is(err, context.Canceled) || c.ShadowFailures() != 1 {
		t.Fatal(err, c.ShadowFailures())
	}
}
func TestReviewR2CallbackPanicPreservesOrdinaryError(t *testing.T) {
	sentinel := errors.New("ordinary transport fault")
	c, _ := stageDTestClient(t, func(r *http.Request) (*http.Response, error) { return nil, sentinel })
	c.shadow = &panicEveryObserver{newTestShadowObserver(), "verdict"}
	_, _, err := c.authorizeAtDecodeSeam(t.Context(), strings.Repeat("a", 64), map[string]any{}, spendlease.EstimateRequest{})
	if !errors.Is(err, sentinel) || c.ShadowFailures() != 1 {
		t.Fatal(err, c.ShadowFailures())
	}
}
func TestReviewR2ConcurrentCancellationDoesNotHideDenial(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	status, reason := shadowErrorForCaller(ctx, &ControlPlaneError{StatusCode: 402, Reason: "billing_denied"})
	if status != 402 || reason != "billing_denied" {
		t.Fatal("caller cancellation hid a real router verdict", status, reason)
	}
}
