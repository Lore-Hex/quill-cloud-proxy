//go:build !cloud_azure

package main

import (
	"context"
	"os"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"golang.org/x/crypto/acme/autocert"
)

func configuredACMECache(_ context.Context, _ *types.BootstrapData) (autocert.Cache, error) {
	return enclavetls.NewACMECache(
		os.Getenv("QUILL_ACME_CACHE_DIR"),
		os.Getenv("QUILL_ACME_CACHE_GCS_BUCKET"),
	)
}
