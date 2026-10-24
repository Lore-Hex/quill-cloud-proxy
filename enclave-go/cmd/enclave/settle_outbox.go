package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/settleoutbox"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
)

// settleOutboxBucketEnv names the GCS bucket the durable settle outbox writes
// to. Unset or empty means the outbox is off and a lost settle stays a log
// line, as before. The objects hold frozen terminals, which carry no prompt,
// output, key or token, so the bucket is launch configuration like
// QUILL_ACME_CACHE_GCS_BUCKET rather than a measured constant like the Batch
// bucket; the writes still go out under the Confidential Space federated
// identity (see infra/gcp/settle-outbox/main.tf for what that does and does
// not gate).
const settleOutboxBucketEnv = "QUILL_SETTLE_OUTBOX_BUCKET"

// settleOutboxSweepEnv turns the sweeper on: "on" (any case) and nothing
// else. It is separate from the bucket so the store can ship and run first
// and the sweeper be enabled later; without the bucket it does nothing. The
// sweeper replays parked terminals written by every boot in the pool, so
// enabling it on one boot is enough and enabling it on all is safe: the
// lease objects serialize them.
const settleOutboxSweepEnv = "QUILL_SETTLE_OUTBOX_SWEEP"

func settleOutboxBucket() string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(os.Getenv(settleOutboxBucketEnv)), "gs://"))
}

func settleOutboxSweepEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(settleOutboxSweepEnv)), "on")
}

// settleOutboxPlan is an outbox that is configured and can be written to from
// this build, before it is started. nil means off. It exists so the boot
// registration can declare capabilities.settle_outbox before any registration
// starts, while the writer itself starts later, once the boot's signer exists.
type settleOutboxPlan struct {
	bucket string
	store  settleoutbox.Store
}

// Configured reports whether this boot will park terminals: the declaration
// the boot registration makes. A boot that cannot park never claims it.
func (p *settleOutboxPlan) Configured() bool { return p != nil }

// prepareSettleOutbox resolves the configuration. It contacts nothing.
func prepareSettleOutbox(bucket string, newStore func(bucket string) (settleoutbox.Store, error)) *settleOutboxPlan {
	if bucket == "" {
		fmt.Fprintln(os.Stderr, "enclave.settle_outbox_disabled reason=no_bucket")
		return nil
	}
	store, err := newStore(bucket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.settle_outbox_disabled reason=%q bucket=%q\n", err.Error(), bucket)
		return nil
	}
	return &settleOutboxPlan{bucket: bucket, store: store}
}

// startSettleOutbox starts the writer for a prepared plan. signer is the boot
// key the control plane was told about at registration
// (Client.RegisteredBootSigner); nil means parked objects carry no boot_auth
// and are unverified. nil plan returns nil, which every caller treats as
// inert.
func startSettleOutbox(ctx context.Context, plan *settleOutboxPlan, signer spendlease.DigestSigner) *settleoutbox.Writer {
	if plan == nil {
		return nil
	}
	writer := settleoutbox.NewWriter(plan.store, signer, func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	})
	writer.Start(ctx)
	fmt.Fprintf(os.Stderr, "enclave.settle_outbox_started bucket=%q boot_signed=%t\n", plan.bucket, signer != nil)
	return writer
}

// startSettleOutboxSweeper starts the sweeper for a prepared plan when sweep
// (QUILL_SETTLE_OUTBOX_SWEEP=on) is set. It replays through replay, this
// boot's control-plane client, so a replay goes to the authority the object
// names with the same egress the retry queue uses. nil when the outbox is
// off (no bucket, or not a GCP build) or sweep is not set; every caller
// treats nil as inert.
func startSettleOutboxSweeper(ctx context.Context, plan *settleOutboxPlan, sweep bool, replay settleoutbox.Replayer) *settleoutbox.Sweeper {
	switch {
	case plan == nil:
		if sweep {
			fmt.Fprintln(os.Stderr, "enclave.settle_outbox_sweeper_disabled reason=no_outbox")
		}
		return nil
	case !sweep:
		fmt.Fprintln(os.Stderr, "enclave.settle_outbox_sweeper_disabled reason=sweep_off")
		return nil
	case replay == nil:
		fmt.Fprintln(os.Stderr, "enclave.settle_outbox_sweeper_disabled reason=no_control_plane")
		return nil
	}
	sweeper := settleoutbox.NewSweeper(plan.store, replay, func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	})
	sweeper.Start(ctx)
	fmt.Fprintf(os.Stderr, "enclave.settle_outbox_sweeper_started bucket=%q interval_ms=%d page_size=%d\n",
		plan.bucket, settleoutbox.DefaultSweepInterval.Milliseconds(), settleoutbox.DefaultSweepPageSize)
	return sweeper
}
