//go:build !cloud_aws

package llm

import (
	"strings"
	"testing"
)

func TestNewImageFetchRequestSetsPublicFetcherHeaders(t *testing.T) {
	req, err := newImageFetchRequest(t.Context(), "https://example.com/image.jpg")
	if err != nil {
		t.Fatalf("newImageFetchRequest: %v", err)
	}
	if got := req.Header.Get("Accept"); !strings.Contains(got, "image/jpeg") || !strings.Contains(got, "image/png") {
		t.Fatalf("Accept = %q, want jpeg and png", got)
	}
	if got := req.Header.Get("User-Agent"); !strings.Contains(got, "TrustedRouter-ImageFetcher") {
		t.Fatalf("User-Agent = %q, want TrustedRouter image fetcher", got)
	}
}
