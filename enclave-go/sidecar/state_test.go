package main

import (
	"errors"
	"testing"
	"time"
)

func TestSnapshotRefusesCurrentProofAfterLatestVerificationFailure(t *testing.T) {
	t.Parallel()

	s := &state{}
	s.set(&verifiedPayload{
		FP:         "verified-fingerprint",
		VerifiedAt: time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}, nil)
	s.set(nil, errors.New("latest full verification failed"))

	if _, err := s.snapshot(); err == nil {
		t.Fatal("snapshot() error = nil, want latest verification failure")
	}
}
