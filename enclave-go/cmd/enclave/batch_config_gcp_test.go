//go:build cloud_gcp

package main

import "testing"

func TestProductionBatchConfigIsPinnedToTrustedRouterResources(t *testing.T) {
	t.Setenv("QUILL_BATCH_ARTIFACT_GCS_BUCKET", "attacker-bucket")
	t.Setenv("QUILL_BATCH_ARTIFACT_KMS_KEY", "projects/attacker/keys/key")
	t.Setenv("QUILL_BATCH_WIF_PROVIDER", "//iam.googleapis.com/projects/1/providers/attacker")

	config, enabled := productionBatchConfig()
	if !enabled {
		t.Fatal("GCP batch service must be enabled")
	}
	if config.Bucket != "quill-cloud-proxy-batch-artifacts" {
		t.Fatalf("bucket is not pinned: %q", config.Bucket)
	}
	if config.KMSKey != "projects/quill-cloud-proxy/locations/us-central1/keyRings/trusted-router/cryptoKeys/batch-envelope" {
		t.Fatalf("KMS key is not pinned: %q", config.KMSKey)
	}
	if config.WIFProvider != "//iam.googleapis.com/projects/44325983244/locations/global/workloadIdentityPools/trustedrouter-batch/providers/confidential-space" {
		t.Fatalf("WIF provider is not pinned: %q", config.WIFProvider)
	}
}
