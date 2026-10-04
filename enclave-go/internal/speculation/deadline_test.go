package speculation

import (
	"math"
	"testing"
	"time"
)

func TestOriginalDeadlineBoundaries(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		name   string
		offset time.Duration
		reason Reason
	}{{"iat", 0, ReasonEligible}, {"plus27", 27 * time.Second, ReasonEligible}, {"before28", 28*time.Second - time.Nanosecond, ReasonEligible}, {"plus28", 28 * time.Second, ReasonDeadline}, {"after28", 29 * time.Second, ReasonDeadline}} {
		t.Run(tc.name, func(t *testing.T) {
			g, r := ReceiveGrant(h.real, time.Unix(1700000000, 0).Add(tc.offset), Monotonic(tc.offset), 0)
			if r != tc.reason {
				t.Fatalf("want %s got %s", tc.reason, r)
			}
			if r == ReasonEligible && (!g.live(Monotonic(tc.offset)) || g.live(Monotonic(28*time.Second)) || g.deadline != Monotonic(28*time.Second)) {
				t.Fatal("original deadline lost")
			}
		})
	}
	for _, field := range []string{"start_before", "exp", "key_expires_at", "price_expires_at", "trust_fresh_until"} {
		t.Run(field, func(t *testing.T) {
			claims, _ := h.real.Claims()
			context := m(loadFixture(t, "grant-permit-tokens.json")["context"])
			limit := int64(1700000012)
			deadline := int64(1700000010)
			if field == "start_before" {
				limit = deadline
			}
			if field == "price_expires_at" {
				m(claims["route"])[field] = limit
				m(context["route"])[field] = limit
			} else {
				claims[field] = limit
			}
			g, err := VerifyGrant(signedEligibilityToken(t, h, claims, RealTyp), h.keys, context, 1700000000, false)
			if err != nil {
				t.Fatal(err)
			}
			if g.StartDeadline() != deadline {
				t.Fatal(g.StartDeadline())
			}
			received, r := ReceiveGrant(g, time.Unix(1700000007, 0), Monotonic(7*time.Second), 0)
			if r != ReasonEligible || !received.live(Monotonic(10*time.Second-1)) || received.live(Monotonic(10*time.Second)) {
				t.Fatal(received, r)
			}
			if _, r = ReceiveGrant(g, time.Unix(deadline, 0), Monotonic(10*time.Second), 0); r != ReasonDeadline {
				t.Fatal("dead on arrival", r)
			}
		})
	}
}
func TestLateGrantCannotGainReceiptTTL(t *testing.T) {
	h := newHarness(t)
	g, r := ReceiveGrant(h.real, time.Unix(1700000027, 500000000), Monotonic(100*time.Second), 0)
	if r != ReasonEligible || !g.live(Monotonic(100*time.Second)) || g.live(Monotonic(100*time.Second+500*time.Millisecond)) {
		t.Fatal(g, r)
	}
	if _, r := ReceiveGrant(h.real, time.Unix(1700000029, 0), Monotonic(200*time.Second), 0); r != ReasonDeadline {
		t.Fatal("late grant allowed", r)
	}
}
func TestClockSkewOnlyShortens(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name string
		wall time.Time
		mono Monotonic
		skew time.Duration
		want Reason
	}{
		{"zero_grant", time.Unix(1700000000, 0), 0, 0, ReasonGrant},
		{"negative_uncertainty", time.Unix(1700000000, 0), 0, -1, ReasonClock},
		{"negative_monotonic", time.Unix(1700000000, 0), -1, 0, ReasonClock},
		{"before_iat", time.Unix(1699999999, 0), 0, 0, ReasonClock},
		{"uncertainty_expired", time.Unix(1700000027, 0), 0, time.Second, ReasonDeadline},
		{"overflow", time.Unix(1700000000, 0), Monotonic(math.MaxInt64), 0, ReasonClock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := h.real
			if tc.name == "zero_grant" {
				g = VerifiedGrant{}
			}
			if _, r := ReceiveGrant(g, tc.wall, tc.mono, tc.skew); r != tc.want {
				t.Fatal(r)
			}
		})
	}
	g, r := ReceiveGrant(h.real, time.Unix(1700000005, 0), Monotonic(50*time.Second), 2*time.Second)
	if r != ReasonEligible || g.deadline != Monotonic(71*time.Second) || g.live(Monotonic(49*time.Second)) || g.live(Monotonic(71*time.Second)) {
		t.Fatal(g, r)
	}
	// Evaluation takes no wall clock: forward or backward wall jumps cannot
	// change the already frozen deadline, and monotonic rollback fails closed.
	if !g.live(Monotonic(70*time.Second)) || (ReceivedGrant{}).live(0) {
		t.Fatal("clock check")
	}
}
