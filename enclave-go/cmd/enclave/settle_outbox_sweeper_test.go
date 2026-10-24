package main

import (
	"net/http"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/settleoutbox"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// The sweeper runs only when both QUILL_SETTLE_OUTBOX_BUCKET (the store) and
// QUILL_SETTLE_OUTBOX_SWEEP=on are set; either alone leaves it off, so the
// store can ship first and the sweeper be enabled on its own.
func TestSettleOutboxSweeperIsOffUnlessBothEnvsAreSet(t *testing.T) {
	gateway := trustedrouter.New("http://127.0.0.1:18080", "internal", &http.Client{})
	for _, tc := range []struct {
		name    string
		bucket  string
		sweep   string
		started bool
	}{
		{"neither", "", "", false},
		{"bucket_only", "outbox-bucket", "", false},
		{"sweep_only", "", "on", false},
		{"sweep_not_on", "outbox-bucket", "true", false},
		{"both", "outbox-bucket", "on", true},
		{"both_any_case", "outbox-bucket", " ON ", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(settleOutboxBucketEnv, tc.bucket)
			t.Setenv(settleOutboxSweepEnv, tc.sweep)
			plan := prepareSettleOutbox(settleOutboxBucket(), func(string) (settleoutbox.Store, error) { return newOutboxTestStore(), nil })
			sweeper := startSettleOutboxSweeper(t.Context(), plan, settleOutboxSweepEnabled(), gateway)
			if (sweeper != nil) != tc.started {
				t.Fatalf("sweeper started = %t, want %t", sweeper != nil, tc.started)
			}
		})
	}
}

// Without a control-plane client there is nothing to replay through.
func TestSettleOutboxSweeperNeedsAControlPlaneClient(t *testing.T) {
	plan := prepareSettleOutbox("outbox-bucket", func(string) (settleoutbox.Store, error) { return newOutboxTestStore(), nil })
	if sweeper := startSettleOutboxSweeper(t.Context(), plan, true, nil); sweeper != nil {
		t.Fatal("sweeper started without a replayer")
	}
}
