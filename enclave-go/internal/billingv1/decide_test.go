package billingv1

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestDecideEligibilityAndEnvelope(t *testing.T) {
	raw, err := os.ReadFile(fixtureDir + "decide_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		AuthorizeResponse struct {
			Data struct {
				Snapshot json.RawMessage `json:"billing_snapshot"`
			} `json:"data"`
		} `json:"authorize_response"`
		Terminal TerminalEnvelope `json:"terminal"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture decode failed")
	}
	snapshot, err := ParseSnapshot(f.AuthorizeResponse.Data.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		route              string
		streamed, eligible bool
	}{
		{"decide", false, true}, {"decide", true, false}, {"embeddings", false, false}, {"other", false, false}, {"chat.completions", true, true}, {"responses", true, true},
	} {
		t.Run(tc.route+map[bool]string{false: "/plain", true: "/streamed"}[tc.streamed], func(t *testing.T) {
			facts := DefaultEligibility()
			facts.RouteType = tc.route
			facts.Streamed = tc.streamed
			err := RequireEligible(facts)
			if (err == nil) != tc.eligible {
				t.Fatal("eligibility differs")
			}
			if !tc.eligible {
				var typed *Error
				if !errors.As(err, &typed) || typed.Code != "unsupported_route" {
					t.Error("wrong exclusion")
				}
			}
			terminal := f.Terminal
			terminal.RouteType = tc.route
			terminal.Streamed = tc.streamed
			if (ValidateEnvelope(snapshot, terminal) == nil) != tc.eligible {
				t.Error("envelope eligibility differs")
			}
			if tc.eligible {
				encoded, err := CanonicalBytes(terminal)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = ParseEnvelope(encoded); err != nil {
					t.Fatal("eligible envelope cannot round trip")
				}
			}
		})
	}
}
