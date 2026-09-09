package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Opt-in verification of a locally captured evidence envelope. This contacts
// Intel and NVIDIA, but sends no prompt or inference request.
func TestLiveChutesEvidence(t *testing.T) {
	path := os.Getenv("TR_LIVE_CHUTES_EVIDENCE_PATH")
	if path == "" {
		t.Skip("set TR_LIVE_CHUTES_EVIDENCE_PATH to a captured evidence envelope")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var request chutesVerificationRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	verifier, err := newChutesVerifier()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := verifier.verify(ctx, &request); err != nil {
		t.Fatal(err)
	}
}
