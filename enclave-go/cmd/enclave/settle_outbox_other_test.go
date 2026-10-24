//go:build !cloud_gcp

package main

import (
	"net/http"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

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

// The sweeper follows the store: no attested GCS identity, no sweeper, even
// with both environment variables set.
func TestSettleOutboxSweeperStaysOffOutsideGCP(t *testing.T) {
	t.Setenv(settleOutboxBucketEnv, "outbox-bucket")
	t.Setenv(settleOutboxSweepEnv, "on")
	plan := prepareSettleOutbox(settleOutboxBucket(), settleOutboxStore)
	gateway := trustedrouter.New("http://127.0.0.1:18080", "internal", &http.Client{})
	if sweeper := startSettleOutboxSweeper(t.Context(), plan, settleOutboxSweepEnabled(), gateway); sweeper != nil {
		t.Fatal("sweeper started outside GCP")
	}
}
