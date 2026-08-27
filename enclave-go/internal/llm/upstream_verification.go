package llm

import (
	"context"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamcert"
)

// UpstreamVerification is the per-request TEE verification result that a
// provider established before sending inference bytes upstream.
type UpstreamVerification struct {
	Policy     string
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

type upstreamVerificationContextKey struct{}

type upstreamVerificationCarrier struct {
	mu    sync.RWMutex
	value UpstreamVerification
}

// WithUpstreamVerification installs or updates the request-local carrier.
// Updating an existing carrier lets verification performed in a derived
// provider context remain observable to the serving goroutine after InvokeStreaming
// returns. Empty values deliberately clear it between fallback attempts.
func WithUpstreamVerification(ctx context.Context, policy string, verifiedAt, expiresAt time.Time) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = upstreamcert.WithCarrier(ctx)
	upstreamcert.Reset(ctx)
	value := UpstreamVerification{Policy: policy, VerifiedAt: verifiedAt, ExpiresAt: expiresAt}
	if carrier, ok := ctx.Value(upstreamVerificationContextKey{}).(*upstreamVerificationCarrier); ok && carrier != nil {
		carrier.mu.Lock()
		carrier.value = value
		carrier.mu.Unlock()
		return ctx
	}
	carrier := &upstreamVerificationCarrier{value: value}
	return context.WithValue(ctx, upstreamVerificationContextKey{}, carrier)
}

// UpstreamCertSHA256FromContext returns the certainly-attributed WebPKI leaf
// fingerprint for the request, if one was observed.
func UpstreamCertSHA256FromContext(ctx context.Context) (string, bool) {
	return upstreamcert.FromContext(ctx)
}

// FromContext returns a structurally complete verification record. Receipt
// verifiers bind its timestamps to the signed iat.
func FromContext(ctx context.Context) (UpstreamVerification, bool) {
	if ctx == nil {
		return UpstreamVerification{}, false
	}
	carrier, ok := ctx.Value(upstreamVerificationContextKey{}).(*upstreamVerificationCarrier)
	if !ok || carrier == nil {
		return UpstreamVerification{}, false
	}
	carrier.mu.RLock()
	value := carrier.value
	carrier.mu.RUnlock()
	if value.Policy == "" || value.VerifiedAt.IsZero() || value.ExpiresAt.IsZero() || !value.ExpiresAt.After(value.VerifiedAt) {
		return UpstreamVerification{}, false
	}
	return value, true
}
