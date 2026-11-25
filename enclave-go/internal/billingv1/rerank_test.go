package billingv1

import (
	"errors"
	"testing"
)

func TestRerankBillingExcluded(t *testing.T) {
	for _, streamed := range []bool{false, true} {
		facts := DefaultEligibility()
		facts.RouteType = "rerank"
		facts.Streamed = streamed
		var typed *Error
		if err := RequireEligible(facts); !errors.As(err, &typed) || typed.Code != "unsupported_route" {
			t.Fatal("rerank must remain outside asynchronous billing")
		}
	}
}
