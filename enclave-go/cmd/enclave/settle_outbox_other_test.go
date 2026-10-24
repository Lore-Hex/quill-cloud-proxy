//go:build !cloud_gcp

package main

import "testing"

// AWS and Azure builds have no attested GCS identity: a configured bucket
// still leaves the outbox off, with the reason logged.
func TestSettleOutboxStaysOffOutsideGCP(t *testing.T) {
	if _, err := settleOutboxStore("outbox-bucket"); err == nil || err.Error() != "unsupported_cloud" {
		t.Fatalf("settleOutboxStore = %v", err)
	}
	plan := prepareSettleOutbox("outbox-bucket", settleOutboxStore)
	if plan.Configured() {
		t.Fatal("outbox configured outside GCP: the boot would declare settle_outbox and never park")
	}
	if writer := startSettleOutbox(t.Context(), plan, nil); writer != nil {
		t.Fatal("outbox started outside GCP")
	}
}
