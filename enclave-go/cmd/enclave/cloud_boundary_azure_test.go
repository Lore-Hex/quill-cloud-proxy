//go:build cloud_azure

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const azureTestCacheKey = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="

func clearAzureBoundaryEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"GOOGLE_APPLICATION_CREDENTIALS",
		"QUILL_ACME_CACHE_GCS_BUCKET",
		"QUILL_ACME_DNS_GCP_PROJECT",
		"QUILL_ACME_DNS_MANAGED_ZONE",
		"QUILL_AZURE_ACME_STORAGE_ACCOUNT",
		"QUILL_AZURE_ACME_STORAGE_CONTAINER",
		"QUILL_AZURE_MI_CLIENT_ID",
	} {
		t.Setenv(name, "")
	}
}

func TestAzureRejectsCrossCloudCredential(t *testing.T) {
	clearAzureBoundaryEnv(t)
	boot := &types.BootstrapData{GCPServiceAccountKeyJSON: `{"type":"service_account"}`}
	if err := configureCrossCloudCredentials(boot); err == nil || !strings.Contains(err.Error(), "refuses") {
		t.Fatalf("error = %v, want Azure cloud-boundary rejection", err)
	}
}

func TestAzureRejectsAmbientGoogleCredential(t *testing.T) {
	clearAzureBoundaryEnv(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/google.json")
	if err := configureCrossCloudCredentials(&types.BootstrapData{}); err == nil ||
		!strings.Contains(err.Error(), "GOOGLE_APPLICATION_CREDENTIALS") {
		t.Fatalf("error = %v, want ambient Google credential rejection", err)
	}
}

func TestAzureACMECacheUsesOnlyAzureCoordinates(t *testing.T) {
	clearAzureBoundaryEnv(t)
	t.Setenv("QUILL_AZURE_ACME_STORAGE_ACCOUNT", "trcache")
	t.Setenv("QUILL_AZURE_ACME_STORAGE_CONTAINER", "acme-cache")
	cache, err := configuredACMECache(context.Background(), &types.BootstrapData{
		AzureACMECacheKey: azureTestCacheKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cache == nil {
		t.Fatal("configuredACMECache returned nil")
	}
}

func TestAzureACMECacheRejectsGCPStorageAndDNS(t *testing.T) {
	for _, variable := range []string{
		"QUILL_ACME_CACHE_GCS_BUCKET",
		"QUILL_ACME_DNS_GCP_PROJECT",
		"QUILL_ACME_DNS_MANAGED_ZONE",
	} {
		t.Run(variable, func(t *testing.T) {
			clearAzureBoundaryEnv(t)
			t.Setenv(variable, "forbidden")
			_, err := configuredACMECache(context.Background(), &types.BootstrapData{
				AzureACMECacheKey: azureTestCacheKey,
			})
			if err == nil || !strings.Contains(err.Error(), "refuses") {
				t.Fatalf("error = %v, want Azure cloud-boundary rejection", err)
			}
		})
	}
}

func TestAzureBYOKCacheFailsClosed(t *testing.T) {
	if cache := newBYOKSecretCache(); cache != nil {
		t.Fatal("Azure must not construct a GCP KMS BYOK cache")
	}
}
