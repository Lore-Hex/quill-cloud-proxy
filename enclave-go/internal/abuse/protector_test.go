package abuse

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/authcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func testProtector(t *testing.T, burst int) (*Protector, context.Context) {
	t.Helper()
	now := time.Unix(1_700_000_000, 0)
	protector := NewProtector(
		authcache.New(45*time.Second, 100),
		NewLimiter(10, burst, 100),
	)
	protector.now = func() time.Time { return now }
	ctx := WithDirectClientIP(t.Context(), testAddr("192.0.2.10:44321"))
	return protector, ctx
}

func TestValidKeyIsNeverCachedNegativeAndNeverDrainsLimiter(t *testing.T) {
	protector, baseCtx := testProtector(t, 30)
	lookupHash := trustedrouter.LookupHash("valid-key")
	for range 1_000 {
		ctx := WithRequestState(baseCtx, &RequestState{})
		if err := protector.BeforeCredentialCheck(ctx, lookupHash); err != nil {
			t.Fatalf("valid key precheck: %v", err)
		}
		protector.AfterCredentialCheck(ctx, lookupHash, nil)
	}
	stats := protector.Stats()
	if stats.CacheOccupancy != 0 || stats.BucketOccupancy != 0 || stats.NegativeCacheHits != 0 || stats.RateLimitedRejects != 0 {
		t.Fatalf("valid key changed abuse state: %+v", stats)
	}
}

func TestTransientFailureIsNotCachedAndIsRetriedNextRequest(t *testing.T) {
	protector, baseCtx := testProtector(t, 30)
	lookupHash := trustedrouter.LookupHash("paying-customer")
	transient := &trustedrouter.ControlPlaneError{StatusCode: http.StatusServiceUnavailable, Type: "unavailable"}
	firstCtx := WithRequestState(baseCtx, &RequestState{})
	protector.AfterCredentialCheck(firstCtx, lookupHash, transient)
	secondCtx := WithRequestState(baseCtx, &RequestState{})
	if err := protector.BeforeCredentialCheck(secondCtx, lookupHash); err != nil {
		t.Fatalf("transient failure was cached: %v", err)
	}
	if stats := protector.Stats(); stats.CacheOccupancy != 0 || stats.BucketOccupancy != 0 {
		t.Fatalf("transient failure changed abuse state: %+v", stats)
	}
}

func TestNegativeCacheHitsCountAsFailuresThenRateLimitBeforeControlPlane(t *testing.T) {
	protector, baseCtx := testProtector(t, 2)
	lookupHash := trustedrouter.LookupHash("invalid-key")
	invalid := &trustedrouter.ControlPlaneError{StatusCode: http.StatusUnauthorized, Type: "invalid_api_key"}
	firstCtx := WithRequestState(baseCtx, &RequestState{})
	protector.AfterCredentialCheck(firstCtx, lookupHash, invalid)

	secondCtx := WithRequestState(baseCtx, &RequestState{})
	err := protector.BeforeCredentialCheck(secondCtx, lookupHash)
	var controlErr *trustedrouter.ControlPlaneError
	if !errors.As(err, &controlErr) || controlErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cache hit error = %#v, want 401", err)
	}

	thirdCtx := WithRequestState(baseCtx, &RequestState{})
	err = protector.BeforeCredentialCheck(thirdCtx, trustedrouter.LookupHash("another-key"))
	if !errors.As(err, &controlErr) || controlErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over-limit error = %#v, want 429", err)
	}
	stats := protector.Stats()
	if stats.NegativeCacheHits != 1 || stats.RateLimitedRejects != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestTrustedRouterTransientControlPlaneFailureIsNotCachedAndRetriesNextRequest(t *testing.T) {
	protector, baseCtx := testProtector(t, 30)
	calls := 0
	client := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			status := http.StatusServiceUnavailable
			body := `{"error":{"message":"temporarily unavailable","type":"unavailable"}}`
			if calls == 2 {
				status = http.StatusOK
				body = `{"data":{"workspace_id":"ws-paying","api_key_hash":"stored-digest"}}`
			}
			return &http.Response{
				StatusCode: status,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		}),
	})
	client.SetCredentialGuard(protector)

	firstCtx := WithRequestState(baseCtx, &RequestState{})
	if _, err := client.ValidateKeyInfo(firstCtx, "valid-paying-key", "responses"); err == nil {
		t.Fatal("first transient request unexpectedly succeeded")
	}
	secondCtx := WithRequestState(baseCtx, &RequestState{})
	if _, err := client.ValidateKeyInfo(secondCtx, "valid-paying-key", "responses"); err != nil {
		t.Fatalf("second request was not retried: %v", err)
	}
	if calls != 2 {
		t.Fatalf("control-plane calls = %d, want 2", calls)
	}
	if stats := protector.Stats(); stats.CacheOccupancy != 0 || stats.BucketOccupancy != 0 {
		t.Fatalf("transient failure changed abuse state: %+v", stats)
	}
}

func TestTrustedRouterNegativeCacheHitRejectsWithoutSecondControlPlaneCall(t *testing.T) {
	protector, baseCtx := testProtector(t, 30)
	calls := 0
	client := trustedrouter.New("https://trustedrouter.com", "internal", &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(
					`{"error":{"message":"Invalid API key","type":"invalid_api_key"}}`,
				)),
			}, nil
		}),
	})
	client.SetCredentialGuard(protector)

	firstCtx := WithRequestState(baseCtx, &RequestState{})
	_, _ = client.ValidateKeyInfo(firstCtx, "invalid-key", "responses")
	secondCtx := WithRequestState(baseCtx, &RequestState{})
	_, err := client.ValidateKeyInfo(secondCtx, "invalid-key", "responses")
	var controlErr *trustedrouter.ControlPlaneError
	if !errors.As(err, &controlErr) || controlErr.StatusCode != http.StatusUnauthorized || controlErr.Type != OutcomeCachedReject {
		t.Fatalf("second error = %#v, want cached 401", err)
	}
	if calls != 1 {
		t.Fatalf("control-plane calls = %d, want 1", calls)
	}
}
