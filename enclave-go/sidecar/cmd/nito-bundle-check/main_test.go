package main

import (
	"strings"
	"testing"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

func TestRejectInvalidInputs(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, tc := range []struct{ raw, pin string }{
		{"{}", ""}, {"{}", digest}, {"not JSON", digest}, {strings.Repeat(" ", maxBundle+1), digest},
		{`{"verification":{"hpke_public_key":"provider-assertion"}}`, digest},
	} {
		if _, err := verify(strings.NewReader(tc.raw), tc.pin, time.Now()); err == nil {
			t.Fatal("unverified evidence accepted")
		}
	}
}

func TestRelayCannotSubstituteTransport(t *testing.T) {
	v := client.GroundTruth{Digest: "current", EnclaveHost: "example.tinfoil.sh", HPKEPublicKey: "key", TLSPublicKey: "tls"}
	if !sameTransport(&v, &v) {
		t.Fatal("identical transport rejected")
	}
	for _, field := range []string{"host", "digest", "hpke", "tls"} {
		c := v
		switch field {
		case "host":
			c.EnclaveHost = "other.tinfoil.sh"
		case "digest":
			c.Digest = "previous"
		case "hpke":
			c.HPKEPublicKey = "another"
		case "tls":
			c.TLSPublicKey = "another"
		}
		if sameTransport(&v, &c) {
			t.Fatalf("changed %s accepted", field)
		}
	}
}
