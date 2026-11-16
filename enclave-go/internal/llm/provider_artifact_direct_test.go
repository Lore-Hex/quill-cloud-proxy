//go:build !cloud_aws

package llm

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestProductionArtifactClientIsSeparateAndReadOnly(t *testing.T) {
	provider := NewProviderHTTPClient()
	defer provider.CloseIdleConnections()
	artifact, err := ProviderArtifactHTTPClient(provider, "https://cdn.example/result.mp4?signature=test")
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.CloseIdleConnections()
	if artifact == provider {
		t.Fatal("CDN added to inference client")
	}
	guard, ok := artifact.Transport.(*artifactReadOnlyTransport)
	if !ok {
		t.Fatalf("unguarded artifact transport %T", artifact.Transport)
	}
	calls := 0
	guard.base = byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		req, _ := http.NewRequest(method, "https://cdn.example/result.mp4?signature=test", nil)
		if method == http.MethodPost {
			req.Body = http.NoBody
		} else {
			req.Header.Set("X-Goog-Api-Key", "secret")
		}
		if _, err := artifact.Do(req); !errors.Is(err, errProviderEgress) {
			t.Fatalf("%s: %v", method, err)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, "https://cdn.example/v1", strings.NewReader("prompt"))
	if _, err := provider.Do(req); !errors.Is(err, errProviderEgress) {
		t.Fatalf("inference policy widened: %v", err)
	}
	if calls != 0 {
		t.Fatal("credential or prompt reached artifact transport")
	}
}
