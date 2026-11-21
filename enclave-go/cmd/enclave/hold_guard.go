package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// refundHold refunds auth and, when the refund cannot be delivered, hands the
// same refund to the settlement retry queue (and through it the settle outbox).
// A refund is a single attempt with its own deadline; a call site that discards
// its error leaves the hold to the control plane's expiry sweep whenever that
// one attempt fails. The request's audit id is read from ctx.
func refundHold(ctx context.Context, gateway *trustedrouter.Client, auth *trustedrouter.Authorization, status int, reason string, elapsedSeconds float64, metadata map[string]any) *trustedrouter.SettleResult {
	return refundFailedStream(ctx, gateway, auth, trustedrouter.RequestLogIDFromContext(ctx), status, reason, elapsedSeconds, metadata)
}

// refundUnclosedHold is a handler's last word on the hold it placed. A handler
// defers it once, before it authorizes; on the way out it refunds a hold for
// which no path attempted a settle or a refund. Every exit is still expected to
// send its own terminal, with the status and reason that fit it. This is what
// keeps an exit that forgets from stranding the caller's credit.
//
// It does nothing for a nil authorization, for one this process did not get
// from an authorize call, and after any settle or refund attempt, failed ones
// included (trustedrouter.Authorization.HoldUnclosed), so it cannot add a
// refund to a request that settled.
func refundUnclosedHold(ctx context.Context, gateway *trustedrouter.Client, auth *trustedrouter.Authorization, route string, started time.Time, metadata map[string]any) {
	if gateway == nil || !gateway.Enabled() || !auth.HoldUnclosed() {
		return
	}
	fmt.Fprintf(os.Stderr,
		"enclave.hold_closed_at_exit request_log_id=%q auth_id=%q route_type=%q\n",
		trustedrouter.RequestLogIDFromContext(ctx), authorizationID(auth), route)
	refundHold(ctx, gateway, auth, 500, "gateway_exit_without_terminal", time.Since(started).Seconds(), metadata)
}
