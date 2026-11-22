package main

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// refundHoldFailures counts refunds sent through refundHold that the control
// plane did not accept.
var refundHoldFailures atomic.Int64

// refundHold sends one refund for auth: a single attempt with the client's own
// deadline, exactly what the `_ = trGateway.Refund(...)` calls it replaces
// did. The one difference is that a failure is no longer silent: it is
// counted and logged, by request and authorization and never by customer.
//
// It does not retry and it queues nothing. A refund that fails leaves the hold
// to the control plane's expiry sweep, as it always has. Retrying refunds
// safely means they can never cost a settle its place in the retry queue, the
// worker's time at shutdown, or its room in the outbox, and that is a change
// of its own. The paths that already queued a failed refund for retry
// (refundFailedStream on the chat and responses stream, and the Polyphemus
// fallback) are untouched and do not come through here.
func refundHold(ctx context.Context, gateway *trustedrouter.Client, auth *trustedrouter.Authorization, status int, reason string, elapsedSeconds float64, metadata map[string]any) {
	if gateway == nil || !gateway.Enabled() || auth == nil {
		return
	}
	if err := gateway.Refund(ctx, auth, status, reason, elapsedSeconds, metadata); err != nil {
		fmt.Fprintf(os.Stderr,
			"enclave.refund_failed request_log_id=%q auth_id=%q error_type=%q error_class=%q failures=%d\n",
			trustedrouter.RequestLogIDFromContext(ctx), authorizationID(auth), reason, controlPlaneErrorClass(err), refundHoldFailures.Add(1))
	}
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
