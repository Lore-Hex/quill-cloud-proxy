package speculation

import "time"

// Monotonic is elapsed time on this boot's monotonic clock. It must never be
// constructed from Unix time or reused across boots.
type Monotonic time.Duration

// ReceivedGrant freezes the receipt-time conversion. Copy it on renewal; never
// recompute its deadline on a cache hit. Its zero value is ineligible.
type ReceivedGrant struct {
	grant              VerifiedGrant
	received, deadline Monotonic
}

// ReceiveGrant converts VerifyGrant's original start deadline exactly once.
// wall and mono must describe the same receipt instant. uncertainty is the
// nonnegative maximum amount by which wall may lag the issuer clock; it only
// shortens rights. Unknown/unbounded clock uncertainty must not call this seam.
// No local clock scheme can compensate for an unreported clock error.
func ReceiveGrant(g VerifiedGrant, wall time.Time, mono Monotonic, uncertainty time.Duration) (ReceivedGrant, Reason) {
	c, err := g.Claims()
	if err != nil || g.Compact() == "" {
		return ReceivedGrant{}, ReasonGrant
	}
	if uncertainty < 0 || mono < 0 || wall.Before(time.Unix(number(c, "iat"), 0)) {
		return ReceivedGrant{}, ReasonClock
	}
	remaining := time.Unix(g.StartDeadline(), 0).Sub(wall.Add(uncertainty))
	if remaining <= 0 {
		return ReceivedGrant{}, ReasonDeadline
	}
	// Verified grants live at most 30 seconds; reject overflow of the local clock.
	deadline := mono + Monotonic(remaining)
	if deadline < mono {
		return ReceivedGrant{}, ReasonClock
	}
	return ReceivedGrant{g, mono, deadline}, ReasonEligible
}

func (g ReceivedGrant) live(now Monotonic) bool {
	return g.grant.Compact() != "" && now >= g.received && now < g.deadline
}
