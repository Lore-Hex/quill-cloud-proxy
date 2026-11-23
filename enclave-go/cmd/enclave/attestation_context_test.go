package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
)

func TestAttestationResponseBudgetAnswersBeforeA20SecondClientTimeout(t *testing.T) {
	// Queue wait plus the caller's own mint must fit one budget that leaves a
	// 20 s client (the synthetic attestation probe) time to read the answer.
	if attestationResponseBudget <= 15*time.Second || attestationResponseBudget >= 20*time.Second {
		t.Fatalf("response budget %s must exceed the 15 s queue wait and stay under 20 s", attestationResponseBudget)
	}
	old := getAttestation
	defer func() { getAttestation = old }()
	getAttestation = func(got context.Context, _, _, _, _, _ []byte) ([]byte, error) {
		deadline, ok := got.Deadline()
		if !ok {
			t.Fatal("issuer call has no deadline")
		}
		if left := time.Until(deadline); left > attestationResponseBudget || left < attestationResponseBudget-5*time.Second {
			t.Fatalf("issuer deadline %s away; want about %s", left, attestationResponseBudget)
		}
		return []byte("doc"), nil
	}
	var response bytes.Buffer
	if !serveAttestationContext(t.Context(), &response, []byte("leaf"), nil, []byte("nonce"), nil) {
		t.Fatalf("response: %s", response.String())
	}
}

func TestAttestationBudgetExpiryIsTheRetryable503(t *testing.T) {
	old, oldBudget := getAttestation, attestationResponseBudget
	defer func() { getAttestation, attestationResponseBudget = old, oldBudget }()
	attestationResponseBudget = 20 * time.Millisecond
	getAttestation = func(got context.Context, _, _, _, _, _ []byte) ([]byte, error) {
		// A launcher stuck behind a slow mint: the queue gives up when the
		// caller's deadline passes, as attestation.tokenQueue does.
		select {
		case <-got.Done():
			return nil, errors.Join(attestation.ErrIssuerUnavailable, got.Err())
		case <-time.After(5 * time.Second):
			return nil, errors.New("no response budget reached the issuer call")
		}
	}
	var response bytes.Buffer
	started := time.Now()
	if serveAttestationContext(t.Context(), &response, []byte("leaf"), nil, []byte("nonce"), nil) {
		t.Fatal("expired budget accepted")
	}
	if !strings.HasPrefix(response.String(), "HTTP/1.1 503") {
		t.Fatalf("response: %s", response.String())
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("answered after %s; the budget did not bound the wait", elapsed)
	}
}

func TestAttestationIssuerUnavailableIsRetryableAndRedacted(t *testing.T) {
	old := getAttestation
	defer func() { getAttestation = old }()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	getAttestation = func(got context.Context, _, _, _, _, _ []byte) ([]byte, error) {
		// The handler adds its response budget on top of the request context;
		// the parent's cancellation must still reach the issuer.
		if !errors.Is(got.Err(), context.Canceled) {
			t.Fatal("request context not forwarded")
		}
		return nil, fmt.Errorf("%w: private issuer evidence", attestation.ErrIssuerUnavailable)
	}
	var response bytes.Buffer
	if serveAttestationContext(ctx, &response, []byte("leaf"), nil, []byte("nonce"), nil) {
		t.Fatal("issuer failure accepted")
	}
	if !strings.HasPrefix(response.String(), "HTTP/1.1 503") {
		t.Fatalf("response: %s", response.String())
	}
	if strings.Contains(response.String(), "private issuer evidence") {
		t.Fatal("issuer detail exposed")
	}
}
