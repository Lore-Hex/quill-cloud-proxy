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
// authorization, so a caller that refunds on true can never refund a hold whose
// terminal was sent some other way.
func (a *Authorization) HoldUnclosed() bool {
	return a != nil && a.hold != nil && !a.hold.terminalAttempted.Load()
}
