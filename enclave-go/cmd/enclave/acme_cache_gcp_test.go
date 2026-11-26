//go:build cloud_gcp

package main

import (
	"context"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
)

func TestGCPCertificateCacheIgnoresLegacyLocations(t *testing.T) {
	t.Setenv("QUILL_ACME_CACHE_DIR", "/not-a-cache")
	t.Setenv("QUILL_ACME_CACHE_GCS_BUCKET", "not-a-production-bucket")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/not-a-credential")
	cache, err := configuredACMECache(context.Background(), nil)
	if err != nil || cache == nil {
		t.Fatal(err)
	}
	if _, err := enclavetls.NewACMECache("", "other"); err == nil {
		t.Fatal("unsealed shared cache available")
	}
}
