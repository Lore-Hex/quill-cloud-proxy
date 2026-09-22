package main

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
)

func TestReceiptRenewalBackoffIsBounded(t *testing.T) {
	for _, tc := range []struct {
		failures int
		want     time.Duration
	}{
		{0, 5 * time.Second}, {1, 5 * time.Second},
		{2, 10 * time.Second}, {3, 20 * time.Second},
		{4, 40 * time.Second}, {5, time.Minute},
		{100, time.Minute}, {math.MaxInt, time.Minute},
	} {
		if got := receiptAttestationRetryDelay(tc.failures); got != tc.want {
			t.Fatalf("failures=%d delay=%s want=%s", tc.failures, got, tc.want)
		}
		for range 20 {
			got := jitteredReceiptAttestationInterval(receiptAttestationRetryDelay(tc.failures))
			if got < tc.want*9/10 || got > tc.want*11/10 {
				t.Fatalf("retry jitter outside bounds: %s", got)
			}
		}
	}
}

func TestReceiptRenewalCancellationStopsPendingRetry(t *testing.T) {
	resetReceiptTestState(t)
	oldGet := getAttestation
	defer func() { getAttestation = oldGet }()
	getAttestation = func(_, _, _, _, _ []byte) ([]byte, error) {
		t.Error("cancelled renewal must not mint")
		return nil, errors.New("unexpected mint")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runReceiptAttestationReminter(ctx, nil, nil, [32]byte{1}, &bytes.Buffer{})
}

func TestReceiptRenewalRetriesFailedMintBeforeNormalCadence(t *testing.T) {
	resetReceiptTestState(t)
	oldGet, oldInterval := getAttestation, receiptAttestationRemintInterval
	defer func() {
		getAttestation, receiptAttestationRemintInterval = oldGet, oldInterval
	}()
	lastGood := newCachedReceiptAttestation([]byte("last-good"), attestation.Kind)
	receiptAttestationCache.Store(lastGood)
	receiptAttestationRemintInterval = time.Millisecond
	var calls atomic.Int32
	getAttestation = func(_, _, _, _, _ []byte) ([]byte, error) {
		if calls.Add(1) == 1 {
			receiptAttestationRemintInterval = time.Hour
			return nil, errors.New("issuer temporarily unavailable")
		}
		return []byte("renewed"), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runReceiptAttestationReminter(ctx, nil, nil, [32]byte{1}, &bytes.Buffer{})
	}()
	deadline := time.Now().Add(7 * time.Second)
	for receiptAttestationCache.Load() == lastGood && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	got := receiptAttestationCache.Load()
	if got == lastGood || got == nil || string(got.document) != "renewed" {
		t.Fatalf("failed renewal was not retried promptly: calls=%d", calls.Load())
	}
	if len(got.previous) != 1 || string(got.previous[0].document) != "last-good" {
		t.Fatal("renewal did not preserve the last-good document in history")
	}
}

func TestReceiptRenewalRetriesMissingInitialEvidence(t *testing.T) {
	resetReceiptTestState(t)
	oldGet, oldInterval := getAttestation, receiptAttestationRemintInterval
	defer func() {
		getAttestation, receiptAttestationRemintInterval = oldGet, oldInterval
	}()
	receiptAttestationCache.Store(nil)
	receiptAttestationRemintInterval = time.Hour
	getAttestation = func(_, _, _, _, _ []byte) ([]byte, error) {
		return []byte("first-good"), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runReceiptAttestationReminter(ctx, nil, nil, [32]byte{1}, &bytes.Buffer{})
	}()
	deadline := time.Now().Add(7 * time.Second)
	for receiptAttestationCache.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if got := receiptAttestationCache.Load(); got == nil || string(got.document) != "first-good" {
		t.Fatal("missing initial evidence waited for the normal hourly cadence")
	}
}
