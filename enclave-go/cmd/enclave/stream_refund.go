package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// A failed response must leave a terminal billing decision, even when the
// immediate refund is unavailable. The retry queue keeps the exact refund for
// recovery while it has room for refunds, and the outbox after it while it has
// room to spare; the control plane still chooses the first terminal winner.
func refundFailedStream(ctx context.Context, gateway *trustedrouter.Client, auth *trustedrouter.Authorization, requestLogID string, status int, reason string, elapsed float64, metadata map[string]any) *trustedrouter.SettleResult {
	if gateway == nil || !gateway.Enabled() || auth == nil {
		return nil
	}
	ctx = trustedrouter.WithRequestLogID(ctx, requestLogID)
	result, err := gateway.RefundDetailed(ctx, auth, status, reason, elapsed, metadata)
	if stageDDispositionLost(result) {
		fmt.Fprintf(os.Stderr, "enclave.stage_d_refund_lost request_log_id=%q auth_id=%q disposition=%q\n", requestLogID, authorizationID(auth), result.Disposition)
	}
	if err != nil {
		settlementRetries.Enqueue(settlementRetryJob{
			cause: err, trGateway: gateway, authorization: auth, requestLogID: requestLogID,
			clientContext: trustedrouter.ClientContextFromContext(ctx), kind: "refund",
			refundStatus: status, refundType: reason, refundElapsed: elapsed, refundMetadata: metadata,
		})
	}
	return result
}
