package authcache

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestIsDefinitiveInvalidCredentialEnumeratesEveryErrorClass(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "invalid key", err: &trustedrouter.ControlPlaneError{StatusCode: 401, Type: "invalid_api_key"}, want: true},
		{name: "unknown spelling the plane never emits is NOT definitive", err: &trustedrouter.ControlPlaneError{StatusCode: 401, Type: "unknown_api_key"}, want: false},
		{name: "another invented spelling is NOT definitive", err: &trustedrouter.ControlPlaneError{StatusCode: 401, Type: "api_key_not_found"}, want: false},
		{name: "revoked spelling the plane never emits is NOT definitive", err: &trustedrouter.ControlPlaneError{StatusCode: 403, Type: "revoked_api_key"}, want: false},
		{name: "alternate revoked spelling is NOT definitive", err: &trustedrouter.ControlPlaneError{StatusCode: 401, Type: "api_key_revoked"}, want: false},
		{name: "bare unauthorized could be internal credential failure", err: &trustedrouter.ControlPlaneError{StatusCode: 401}, want: false},
		{name: "generic forbidden", err: &trustedrouter.ControlPlaneError{StatusCode: 403, Type: "forbidden"}, want: false},
		{name: "bad request", err: &trustedrouter.ControlPlaneError{StatusCode: 400, Type: "bad_request"}, want: false},
		{name: "insufficient credits", err: &trustedrouter.ControlPlaneError{StatusCode: 402, Type: "insufficient_credits"}, want: false},
		{name: "rate limited", err: &trustedrouter.ControlPlaneError{StatusCode: 429, Type: "rate_limit"}, want: false},
		{name: "server error", err: &trustedrouter.ControlPlaneError{StatusCode: 500, Type: "internal_error"}, want: false},
		{name: "bad gateway", err: &trustedrouter.ControlPlaneError{StatusCode: 502, Type: "bad_gateway"}, want: false},
		{name: "service unavailable", err: &trustedrouter.ControlPlaneError{StatusCode: 503, Type: "unavailable"}, want: false},
		{name: "gateway timeout", err: &trustedrouter.ControlPlaneError{StatusCode: 504, Type: "timeout"}, want: false},
		{name: "context canceled", err: context.Canceled, want: false},
		{name: "context deadline", err: context.DeadlineExceeded, want: false},
		{name: "network timeout", err: timeoutError{}, want: false},
		{name: "network failure", err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, want: false},
		{name: "wrapped invalid key", err: fmt.Errorf("authorize: %w", &trustedrouter.ControlPlaneError{StatusCode: 401, Type: "invalid_api_key"}), want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsDefinitiveInvalidCredential(test.err); got != test.want {
				t.Fatalf("IsDefinitiveInvalidCredential(%T) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestCacheTTLAndLRUBoundHoldUnderLookupHashSpray(t *testing.T) {
	cache := New(45*time.Second, 3)
	now := time.Unix(1_700_000_000, 0)
	invalid := &trustedrouter.ControlPlaneError{StatusCode: 401, Type: "invalid_api_key"}
	for index := 0; index < 10_000; index++ {
		cache.Remember(trustedrouter.LookupHash(fmt.Sprintf("spray-%d", index)), invalid, now)
	}
	if got := cache.Len(); got != 3 {
		t.Fatalf("occupancy = %d, want 3", got)
	}
	oldestSurvivor := trustedrouter.LookupHash("spray-9997")
	if !cache.Contains(oldestSurvivor, now.Add(44*time.Second)) {
		t.Fatal("most recent LRU window was not retained")
	}
	if cache.Contains(oldestSurvivor, now.Add(45*time.Second)) {
		t.Fatal("verdict survived its 45-second TTL")
	}
}

func TestCacheRefusesRawBearerKeys(t *testing.T) {
	cache := New(45*time.Second, 3)
	cache.Remember(
		"sk-this-is-raw-credential-material",
		&trustedrouter.ControlPlaneError{StatusCode: 401, Type: "invalid_api_key"},
		time.Now(),
	)
	if got := cache.Len(); got != 0 {
		t.Fatalf("raw bearer changed occupancy to %d", got)
	}
}

func TestCacheRefusesTransientVerdicts(t *testing.T) {
	cache := New(45*time.Second, 3)
	cache.Remember(
		trustedrouter.LookupHash("paying-customer"),
		&trustedrouter.ControlPlaneError{StatusCode: 503, Type: "unavailable"},
		time.Now(),
	)
	if got := cache.Len(); got != 0 {
		t.Fatalf("transient verdict changed occupancy to %d", got)
	}
}
