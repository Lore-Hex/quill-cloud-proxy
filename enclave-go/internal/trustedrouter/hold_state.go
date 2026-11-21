package trustedrouter

import "sync/atomic"

// holdState records whether a terminal (a settle or a refund) has been
// attempted for the credit hold an authorize call placed.
//
// An authorize that succeeds holds the caller's credit until a settle or a
// refund closes it. A handler exit that sends neither strands the hold until
// the control plane's expiry sweep, and every retry of the same failing
// request strands another. Which exits send a terminal used to be each exit's
// job; this record lets a handler check, once, on the way out.
//
// It is held by pointer so that copies of an Authorization share one record:
// the streaming path refunds a copy that names the selected route.
//
// What it is not: it records attempts, it does not arbitrate between them. A
// settle or refund started on one goroutine does not wait for, or stop, one
// started on another, and nothing here makes a settle and a refund exclusive.
// The control plane decides that, by keeping the first terminal it receives.
// The one thing this record makes exclusive is the exit refund itself
// (ClaimUnclosedHold): at most one caller ever gets to send it. Handlers run
// a request on one goroutine and take the claim last, on the way out, so in
// practice nothing races it.
type holdState struct {
	terminalAttempted atomic.Bool
}

// trackHold marks a as a hold this client placed. Only the authorize entry
// points call it, on the authorization the control plane just returned. An
// authorization rebuilt from storage (a video job, a batch handle, a queued
// retry) or built locally (a spend-lease plan before its reserve) is not
// tracked: nothing here can tell whether its terminal is still owed.
func (a *Authorization) trackHold() {
	if a != nil && a.hold == nil {
		a.hold = &holdState{}
	}
}

// noteTerminalAttempt records that a settle or refund was started for a. It is
// recorded at the start of the attempt, not on success: after a settle that
// failed or timed out the charge may have landed or a retry may be queued, and
// a refund must not follow it.
func (a *Authorization) noteTerminalAttempt() {
	if a != nil && a.hold != nil {
		a.hold.terminalAttempted.Store(true)
	}
}

// HoldUnclosed reports whether a is a hold this client placed for which no
// settle and no refund has been attempted. It is false for a nil or untracked
// authorization. It only reads; a caller about to refund on the strength of it
// uses ClaimUnclosedHold instead.
func (a *Authorization) HoldUnclosed() bool {
	return a != nil && a.hold != nil && !a.hold.terminalAttempted.Load()
}

// ClaimUnclosedHold reports true to exactly one caller, and only when a is a
// hold this client placed for which no settle and no refund has been
// attempted. That caller owns the exit refund and must send it; every other
// caller, concurrent or later, gets false. It is false for a nil or untracked
// authorization, so the exit refund can never be sent for a hold whose
// terminal was sent some other way.
func (a *Authorization) ClaimUnclosedHold() bool {
	return a != nil && a.hold != nil && a.hold.terminalAttempted.CompareAndSwap(false, true)
}

// OwnReplay reports whether a is the caller's own hold handed back to it by a
// retry of its own authorize.
//
// An authorize can commit at the control plane and lose its response. The
// client retries the same request, with the same idempotency key and the same
// invocation nonce, and the control plane answers with the stored
// authorization and idempotent_replay set. That authorization is this
// request's hold, placed moments ago, and nothing has run for it: the caller
// serves the request as if the first response had arrived. Answering it with
// an error instead leaves the hold with no terminal.
//
// The other replay, an authorization that belongs to an earlier request whose
// client re-sent its Idempotency-Key, never reaches a caller. The decode
// boundary compares the invocation nonce and returns a 409 instead of an
// authorization (authorizeAtDecodeSeamWithAdmission), and an invocation can
// claim a key only once. Every authorization an authorize entry point returns
// is therefore the caller's own, which is exactly what tracking records, so a
// replayed authorization is the caller's own if and only if it is tracked. One
// that is not (a test double, one rebuilt from storage) is never treated as
// the caller's: it is neither served nor refunded on this basis.
func (a *Authorization) OwnReplay() bool {
	return a != nil && a.IdempotentReplay && a.hold != nil
}
