package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

// The qualification caller supplies its own challenge and peer SPKI via a
// private pipe. Neither value may be sourced from the untrusted report.
func TestFortanixQualificationPipe(t *testing.T) {
	mode := os.Getenv("FORTANIX_QUALIFICATION")
	if mode == "" {
		t.Skip("opt-in qualification only")
	}
	if mode != "cpu" && mode != "devices" {
		t.Fatal("unknown qualification mode")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		t.Fatal("invalid qualification envelope")
	}
	var env struct {
		Nonce, SPKI string
		Report      json.RawMessage
	}
	if json.Unmarshal(raw, &env) != nil {
		t.Fatal("invalid qualification input")
	}
	n, e1 := hex.DecodeString(env.Nonce)
	s, e2 := hex.DecodeString(env.SPKI)
	if e1 != nil || e2 != nil || len(n) != 32 || len(s) != 32 {
		t.Fatal("invalid challenge or peer certificate digest")
	}
	if mode == "cpu" {
		_, err = fortanixBoundDevices(env.Report, [32]byte(n), [32]byte(s))
	} else {
		err = appraiseFortanixCandidate(t.Context(), env.Report, [32]byte(n), [32]byte(s))
	}
	if err != nil {
		t.Fatal(err)
	}
}
