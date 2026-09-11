package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Opt-in audit of freshly captured public evidence. No inference credential is
// used here; the separate llm live test proves the same-connection round trip.
func TestLiveNearAIEvidence(t *testing.T) {
	dir := os.Getenv("TR_LIVE_NEAR_AI_EVIDENCE_DIR")
	if dir == "" {
		t.Skip("set TR_LIVE_NEAR_AI_EVIDENCE_DIR to freshly captured evidence")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no evidence fixtures: %v", err)
	}
	v, err := newNearAIVerifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var request nearAIVerificationRequest
			if err := json.Unmarshal(raw, &request); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			if _, err := v.verify(ctx, &request); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Diagnostic only: a platform pass is necessary, never sufficient, for routing.
func TestLiveNearAIPlatformEvidence(t *testing.T) {
	dir := os.Getenv("TR_LIVE_NEAR_AI_EVIDENCE_DIR")
	if dir == "" {
		t.Skip("set TR_LIVE_NEAR_AI_EVIDENCE_DIR")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no evidence fixtures: %v", err)
	}
	v, err := newNearAIVerifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var request nearAIVerificationRequest
			if err := json.Unmarshal(raw, &request); err != nil {
				t.Fatal(err)
			}
			var report nearAIReport
			if err := json.Unmarshal(request.Evidence, &report); err != nil {
				t.Fatal(err)
			}
			if _, err := v.verifyQuote(report.IntelQuote); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			if err := v.verifyNVIDIA(ctx, report.NVIDIAPayload, request.Nonce); err != nil {
				t.Fatal(err)
			}
		})
	}
}
