package llm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testTinfoilFP = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validTestSidecarPayload() *sidecarPayload {
	now := time.Now()
	return &sidecarPayload{
		FP:              testTinfoilFP,
		CodeDigest:      "abcdef0123456789",
		CodeFingerprint: "code-fingerprint",
		EnclaveFP:       "enclave-fingerprint",
		VerifiedAt:      now,
		ExpiresAt:       now.Add(15 * time.Minute),
	}
}

func TestResolveExpectedFPRequiresBothVerificationSources(t *testing.T) {
	t.Parallel()

	verificationError := errors.New("full verifier unavailable")
	rawError := errors.New("independent attestation fetch unavailable")

	tests := []struct {
		name       string
		rawFP      string
		rawErr     error
		verified   *sidecarPayload
		sidecarErr error
		wantErr    bool
	}{
		{
			name:     "both sources agree",
			rawFP:    testTinfoilFP,
			verified: validTestSidecarPayload(),
		},
		{
			name:       "raw only refuses",
			rawFP:      testTinfoilFP,
			sidecarErr: verificationError,
			wantErr:    true,
		},
		{
			name:     "verified only refuses",
			rawErr:   rawError,
			verified: validTestSidecarPayload(),
			wantErr:  true,
		},
		{
			name:       "neither source refuses",
			rawErr:     rawError,
			sidecarErr: verificationError,
			wantErr:    true,
		},
		{
			name:     "disagreement refuses",
			rawFP:    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			verified: validTestSidecarPayload(),
			wantErr:  true,
		},
		{
			name:    "missing verified payload refuses",
			rawFP:   testTinfoilFP,
			wantErr: true,
		},
		{
			name:  "expired verified payload refuses",
			rawFP: testTinfoilFP,
			verified: func() *sidecarPayload {
				payload := validTestSidecarPayload()
				payload.VerifiedAt = time.Now().Add(-20 * time.Minute)
				payload.ExpiresAt = time.Now().Add(-5 * time.Minute)
				return payload
			}(),
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := resolveExpectedFPFromResults(
				test.rawFP,
				test.rawErr,
				test.verified,
				test.sidecarErr,
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("resolveExpectedFPFromResults() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

type recordingRoundTripper struct {
	calls int
	resp  *http.Response
	err   error
}

func (r *recordingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return r.resp, r.err
}

func TestAttestedRoundTripperExpiredProofFailsBeforeUpstream(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC)
	upstream := &recordingRoundTripper{}
	rt := &attestedRoundTripper{
		transport: upstream,
		expiresAt: now.Add(-time.Second),
		resolve: func(context.Context) (*sidecarPayload, error) {
			return nil, errors.New("full verifier unavailable")
		},
		now: func() time.Time { return now },
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://inference.tinfoil.sh/v1/chat/completions", strings.NewReader("secret prompt"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("RoundTrip() error = nil, want verification failure")
	}
	if upstream.calls != 0 {
		t.Fatalf("upstream RoundTrip calls = %d, want 0", upstream.calls)
	}
}

func TestAttestedRoundTripperCurrentProofUsesPinnedTransport(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC)
	upstream := &recordingRoundTripper{resp: &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("ok")),
	}}
	rt := &attestedRoundTripper{
		transport:  upstream,
		expected:   testTinfoilFP,
		verifiedAt: now.Add(-time.Minute),
		expiresAt:  now.Add(time.Minute),
		codeDigest: "abcdef0123456789",
		resolve: func(context.Context) (*sidecarPayload, error) {
			t.Fatal("current proof unexpectedly triggered verification refresh")
			return nil, nil
		},
		check: func(context.Context) (*sidecarPayload, error) {
			payload := validTestSidecarPayload()
			payload.VerifiedAt = now.Add(-time.Minute)
			payload.ExpiresAt = now.Add(time.Minute)
			return payload, nil
		},
		now: func() time.Time { return now },
	}
	requestContext := WithUpstreamVerification(context.Background(), "", time.Time{}, time.Time{})
	req, err := http.NewRequestWithContext(requestContext, http.MethodPost, "https://inference.tinfoil.sh/v1/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	defer resp.Body.Close()
	if upstream.calls != 1 {
		t.Fatalf("upstream RoundTrip calls = %d, want 1", upstream.calls)
	}
	verification, ok := FromContext(requestContext)
	if !ok || verification.Policy != tinfoilReceiptVerificationPolicy || !verification.VerifiedAt.Equal(now.Add(-time.Minute)) || !verification.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("upstream verification = %+v ok=%v", verification, ok)
	}
}

func TestAttestedRoundTripperLatestSidecarFailureFailsBeforeUpstream(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC)
	upstream := &recordingRoundTripper{}
	rt := &attestedRoundTripper{
		transport:  upstream,
		expected:   testTinfoilFP,
		expiresAt:  now.Add(time.Minute),
		codeDigest: "abcdef0123456789",
		resolve: func(context.Context) (*sidecarPayload, error) {
			t.Fatal("current proof unexpectedly triggered verification refresh")
			return nil, nil
		},
		check: func(context.Context) (*sidecarPayload, error) {
			return nil, errors.New("latest full verification failed")
		},
		now: func() time.Time { return now },
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://inference.tinfoil.sh/v1/chat/completions", strings.NewReader("secret prompt"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("RoundTrip() error = nil, want latest-verification failure")
	}
	if upstream.calls != 0 {
		t.Fatalf("upstream RoundTrip calls = %d, want 0", upstream.calls)
	}
}

func TestPinnedTLSDialRejectsNonTinfoilDestinationBeforeDial(t *testing.T) {
	t.Parallel()

	_, err := pinnedTLSDial(testTinfoilFP)(context.Background(), "tcp", "example.com:443")
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("pinnedTLSDial() error = %v, want destination rejection", err)
	}
}

func TestTinfoilRedirectsAreRefused(t *testing.T) {
	t.Parallel()

	if err := refuseTinfoilRedirect(nil, nil); err == nil {
		t.Fatal("refuseTinfoilRedirect() error = nil, want redirect rejection")
	}
}
