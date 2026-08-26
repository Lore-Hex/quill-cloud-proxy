package llm

import (
	"context"
	"testing"
	"time"
)

func TestUpstreamVerificationCarrierPropagatesFromDerivedContextAndClears(t *testing.T) {
	ctx := WithUpstreamVerification(context.Background(), "", time.Time{}, time.Time{})
	derived, cancel := context.WithCancel(ctx)
	defer cancel()
	verifiedAt := time.Unix(1_756_223_940, 0)
	expiresAt := verifiedAt.Add(5 * time.Minute)
	_ = WithUpstreamVerification(derived, "test-policy", verifiedAt, expiresAt)
	got, ok := FromContext(ctx)
	if !ok || got.Policy != "test-policy" || !got.VerifiedAt.Equal(verifiedAt) || !got.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("FromContext = %+v, %v", got, ok)
	}
	_ = WithUpstreamVerification(ctx, "", time.Time{}, time.Time{})
	if got, ok := FromContext(derived); ok {
		t.Fatalf("cleared carrier = %+v, true", got)
	}
}
