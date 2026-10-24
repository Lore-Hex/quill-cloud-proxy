package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/settleoutbox"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
)

// settleOutboxBucketEnv names the GCS bucket the durable settle outbox writes
// to. Unset or empty means the outbox is off and a lost settle stays a log
// line, as before. The objects hold frozen terminals, which carry no prompt,
// output, key or token, so the bucket is launch configuration like
// QUILL_ACME_CACHE_GCS_BUCKET rather than a measured constant like the Batch
// bucket; the writes still go out under the attested Confidential Space
// identity, so only an approved image can create objects there.
const settleOutboxBucketEnv = "QUILL_SETTLE_OUTBOX_BUCKET"

func settleOutboxBucket() string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(os.Getenv(settleOutboxBucketEnv)), "gs://"))
}

// startSettleOutbox starts the outbox writer when a bucket is configured and
// this build has an attested GCS identity. It returns nil when the outbox is
// off; every caller treats nil as inert.
func startSettleOutbox(ctx context.Context, signer *receipt.Signer) *settleoutbox.Writer {
	return buildSettleOutbox(ctx, settleOutboxBucket(), settleOutboxStore, signer)
}

func buildSettleOutbox(
	ctx context.Context,
	bucket string,
	newStore func(bucket string) (settleoutbox.ObjectStore, error),
	signer *receipt.Signer,
) *settleoutbox.Writer {
	if bucket == "" {
		fmt.Fprintln(os.Stderr, "enclave.settle_outbox_disabled reason=no_bucket")
		return nil
	}
	store, err := newStore(bucket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.settle_outbox_disabled reason=%q bucket=%q\n", err.Error(), bucket)
		return nil
	}
	// A nil *receipt.Signer must not become a non-nil interface.
	var digestSigner spendlease.DigestSigner
	if signer != nil {
		digestSigner = signer
	}
	writer := settleoutbox.NewWriter(store, digestSigner, func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	})
	writer.Start(ctx)
	fmt.Fprintf(os.Stderr, "enclave.settle_outbox_started bucket=%q boot_signed=%t\n", bucket, digestSigner != nil)
	return writer
}
