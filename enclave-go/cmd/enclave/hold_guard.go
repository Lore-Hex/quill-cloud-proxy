package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// refundHold refunds auth and, when the refund cannot be delivered, hands the
// same refund to the retry queue. A refund is a single attempt with its own
// deadline; a call site that discards its error leaves the hold to the control
// plane's expiry sweep whenever that one attempt fails. The request's audit id
// is read from ctx.
//
// The retry is best effort and never at a settle's expense: refund retries
// wait in a bounded queue of their own, are sent only when no settle is
// waiting, and are dropped, with a log line, when that queue is full
// (settlementRetryQueue). A dropped refund retry leaves the hold to expire,
// which is what every failed refund did before.
func refundHold(ctx context.Context, gateway *trustedrouter.Client, auth *trustedrouter.Authorization, status int, reason string, elapsedSeconds float64, metadata map[string]any) *trustedrouter.SettleResult {
	return refundFailedStream(ctx, gateway, auth, trustedrouter.RequestLogIDFromContext(ctx), status, reason, elapsedSeconds, metadata)
}

// refundUnclosedHold is a handler's last word on the hold it placed. A handler
// defers it once, around its authorize; on the way out it refunds a hold for
// which no path attempted a settle or a refund. Every exit is still expected to
// send its own terminal, with the status and reason that fit it. This is what
// keeps an exit that forgets from stranding the caller's credit.
//
// It does nothing for a nil authorization, for one this process did not get
// from an authorize call, and after any settle or refund attempt, failed ones
// included, so it cannot add a refund to a request that settled. It claims
// the hold before it refunds (trustedrouter.Authorization.ClaimUnclosedHold),
// so two calls for one authorization, concurrent or not, send one refund.
//
// It is a record of attempts, not arbitration. A settle started elsewhere at
// the same instant as this claim is not held back by it; the control plane
// keeps whichever terminal arrives first. A handler serves its request on one
// goroutine and runs this last, so that race does not arise in the handlers
// that use it.
func refundUnclosedHold(ctx context.Context, gateway *trustedrouter.Client, auth *trustedrouter.Authorization, route string, started time.Time, metadata map[string]any) {
	if gateway == nil || !gateway.Enabled() || !auth.ClaimUnclosedHold() {
		return
	}
	fmt.Fprintf(os.Stderr,
		"enclave.hold_closed_at_exit request_log_id=%q auth_id=%q route_type=%q\n",
		trustedrouter.RequestLogIDFromContext(ctx), authorizationID(auth), route)
	refundHold(ctx, gateway, auth, 500, "gateway_exit_without_terminal", time.Since(started).Seconds(), metadata)
}
