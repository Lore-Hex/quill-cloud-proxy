//go:build cloud_gcp

package main

import "testing"

// A GCP build reaches GCS with the Batch identity: a configured bucket turns
// the outbox on. Nothing is contacted at construction.
func TestSettleOutboxStoreIsAvailableOnGCP(t *testing.T) {
	store, err := settleOutboxStore("outbox-bucket")
	if err != nil || store == nil {
		t.Fatalf("settleOutboxStore = %v, %v", store, err)
	}
}
