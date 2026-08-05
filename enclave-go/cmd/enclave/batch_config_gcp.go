//go:build cloud_gcp

package main

// These resource identities are part of the measured workload. They must not
// be launch-time environment overrides: redirecting either the KMS key or the
// bucket to an operator-controlled project would defeat envelope encryption.
func productionBatchConfig() (batchRuntimeConfig, bool) {
	return batchRuntimeConfig{
		Bucket:      "quill-cloud-proxy-batch-artifacts",
		KMSKey:      "projects/quill-cloud-proxy/locations/us-central1/keyRings/trusted-router/cryptoKeys/batch-envelope",
		WIFProvider: "//iam.googleapis.com/projects/44325983244/locations/global/workloadIdentityPools/trustedrouter-batch/providers/confidential-space",
	}, true
}
