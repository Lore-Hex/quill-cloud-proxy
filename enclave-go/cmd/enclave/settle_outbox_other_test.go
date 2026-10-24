//go:build !cloud_gcp

package main

import "testing"

// AWS and Azure builds have no attested GCS identity: a configured bucket
// still leaves the outbox off, with the reason logged.
func TestSettleOutboxStaysOffOutsideGCP(t *testing.T) {
	if _, err := settleOutboxStore("outbox-bucket"); err == nil || err.Error() != "unsupported_cloud" {
		t.Fatalf("settleOutboxStore = %v", err)
	}
	if writer := buildSettleOutbox(t.Context(), "outbox-bucket", settleOutboxStore, nil); writer != nil {
		t.Fatal("outbox built outside GCP")
	}
}
