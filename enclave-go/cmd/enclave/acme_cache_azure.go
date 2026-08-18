//go:build cloud_azure

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"golang.org/x/crypto/acme/autocert"
)

func configuredACMECache(_ context.Context, boot *types.BootstrapData) (autocert.Cache, error) {
	if strings.TrimSpace(os.Getenv("QUILL_ACME_CACHE_GCS_BUCKET")) != "" {
		return nil, fmt.Errorf("azure build refuses QUILL_ACME_CACHE_GCS_BUCKET")
	}
	if strings.TrimSpace(os.Getenv("QUILL_ACME_DNS_GCP_PROJECT")) != "" ||
		strings.TrimSpace(os.Getenv("QUILL_ACME_DNS_MANAGED_ZONE")) != "" {
		return nil, fmt.Errorf("azure build refuses GCP Cloud DNS credentials")
	}
	return enclavetls.NewAzureBlobCache(enclavetls.AzureBlobCacheOptions{
		Account:       os.Getenv("QUILL_AZURE_ACME_STORAGE_ACCOUNT"),
		Container:     os.Getenv("QUILL_AZURE_ACME_STORAGE_CONTAINER"),
		EncryptionKey: boot.AzureACMECacheKey,
		MIClientID:    os.Getenv("QUILL_AZURE_MI_CLIENT_ID"),
	})
}
