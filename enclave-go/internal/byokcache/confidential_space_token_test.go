//go:build cloud_gcp

package byokcache

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestConfidentialSpaceTokenSourceExchangesAttestationAndCaches(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	mintCalls := 0
	stsCalls := 0
	client := &http.Client{Transport: kmsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		stsCalls++
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("parse body: %v", err)
		}
		if values.Get("subject_token") != "attestation-jwt" || values.Get("audience") != "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/trusted/providers/confidential-space" {
			t.Fatalf("STS values = %#v", values)
		}
		if values.Get("scope") != cloudPlatformScope || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatalf("STS request scope/header = %q / %q", values.Get("scope"), request.Header.Get("Content-Type"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"federated-token-` + string(rune('0'+stsCalls)) + `","expires_in":120,"token_type":"Bearer"}`)),
		}, nil
	})}
	source, err := NewConfidentialSpaceTokenSource(
		"//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/trusted/providers/confidential-space",
		client,
	)
	if err != nil {
		t.Fatalf("NewConfidentialSpaceTokenSource: %v", err)
	}
	source.Now = func() time.Time { return now }
	source.STSEndpoint = "https://sts.invalid/token"
	source.MintToken = func(_ context.Context, audience string) ([]byte, error) {
		mintCalls++
		if audience != confidentialSpaceSTSAudience {
			t.Fatalf("mint audience = %q", audience)
		}
		return []byte("attestation-jwt"), nil
	}

	first, err := source.Token(t.Context())
	if err != nil {
		t.Fatalf("first Token: %v", err)
	}
	second, err := source.Token(t.Context())
	if err != nil || second != first || mintCalls != 1 || stsCalls != 1 {
		t.Fatalf("cached token=%q err=%v mint=%d sts=%d", second, err, mintCalls, stsCalls)
	}
	now = now.Add(91 * time.Second)
	third, err := source.Token(t.Context())
	if err != nil || third == first || mintCalls != 2 || stsCalls != 2 {
		t.Fatalf("refreshed token=%q err=%v mint=%d sts=%d", third, err, mintCalls, stsCalls)
	}
}

func TestNewConfidentialSpaceTokenSourceRejectsNonProviderAudience(t *testing.T) {
	t.Parallel()

	if _, err := NewConfidentialSpaceTokenSource("https://attacker.example", nil); err == nil {
		t.Fatal("accepted invalid provider audience")
	}
}
