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
	// Candidate manifests are allowed only in this explicitly opted-in test.
	// Production continues to use the release-embedded measurement allowlist.
	if candidate := os.Getenv("TR_LIVE_CHUTES_CANDIDATE_MEASUREMENTS_PATH"); candidate != "" {
		raw, err := os.ReadFile(candidate)
		if err != nil {
			t.Fatal(err)
		}
		var measurements []chutesMeasurement
		if err := json.Unmarshal(raw, &measurements); err != nil {
			t.Fatal(err)
		}
		if err := validateChutesMeasurements(measurements); err != nil {
			t.Fatal(err)
		}
		verifier.measurements = measurements
	}
	verifyTDX := verifier.verifyTDX
	verifier.verifyTDX = func(raw []byte) error {
		body, err := verifyTDXQuote(raw, verifyTDX)
		if err != nil {
			return err
		}
		if measurement, err := verifier.matchMeasurement(body); err == nil {
			t.Logf("matched TDX profile version=%s name=%s", measurement.Version, measurement.Name)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := verifier.verify(ctx, &request); err != nil {
		t.Fatal(err)
	}
}
