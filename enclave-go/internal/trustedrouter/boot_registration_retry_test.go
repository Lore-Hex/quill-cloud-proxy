package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
)

func TestBootRegistrationReloadsEvidenceUntilVerified(t *testing.T) {
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	rounds, posts, waits := 0, 0, 0
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		posts++
		if request.URL.Path != spendlease.RegisterPath {
			t.Fatalf("path = %q", request.URL.Path)
		}
		var payload bootRegistrationRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.KID != signer.Kid() || payload.ReceiptPublicKey != signer.JWK() {
			t.Fatal("registration changed the boot identity")
		}
		wantEvidence := []string{"expired", "fresh-but-rejected", "fresh-verified"}[posts-1]
		if payload.AttestationEvidence != wantEvidence || payload.AttestationKind != "gcp-cs-jwt" {
			t.Fatalf("evidence = %#v, want %q", payload, wantEvidence)
		}
		status, body := http.StatusOK, `{"data":{"verified":true}}`
		if posts == 1 {
			status, body = http.StatusForbidden, `{"error":{"message":"expired evidence"}}`
		} else if posts == 2 {
			body = `{"data":{"verified":false}}`
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Request: request, Body: io.NopCloser(strings.NewReader(body))}, nil
	})})
	client.authorizeRetry = retryPolicy{attempts: 1}
	policy := bootRegistrationRetryPolicy()
	policy.sleep = func(_ context.Context, delay time.Duration) error {
		waits++
		if delay < time.Second || delay > time.Minute {
			t.Fatalf("unbounded retry delay %v", delay)
		}
		return nil
	}
	source := func() BootRegistrationEvidence {
		rounds++
		switch rounds {
		case 1:
			return BootRegistrationEvidence{}
		case 2:
			return BootRegistrationEvidence{Attestation: "expired", AttestationKind: "gcp-cs-jwt"}
		case 3:
			return BootRegistrationEvidence{Attestation: "fresh-but-rejected", AttestationKind: "gcp-cs-jwt"}
		default:
			return BootRegistrationEvidence{Attestation: "fresh-verified", AttestationKind: "gcp-cs-jwt"}
		}
	}
	if !client.registerAttestedBoot(t.Context(), signer, source, "test", policy) {
		t.Fatal("recovered evidence never registered")
	}
	if rounds != 4 || posts != 3 || waits != 3 {
		t.Fatalf("rounds=%d posts=%d waits=%d", rounds, posts, waits)
	}
}

func TestBootRegistrationRetriesAfterTransportPolicyExhausted(t *testing.T) {
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	posts, loads := 0, 0
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		posts++
		if posts == 1 {
			return nil, errors.New("temporary connection failure")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: request, Body: io.NopCloser(strings.NewReader(`{"data":{"verified":true}}`))}, nil
	})})
	client.authorizeRetry = retryPolicy{attempts: 1}
	policy := bootRegistrationRetryPolicy()
	policy.sleep = func(context.Context, time.Duration) error { return nil }
	if !client.registerAttestedBoot(t.Context(), signer, func() BootRegistrationEvidence {
		loads++
		return BootRegistrationEvidence{Attestation: "valid", AttestationKind: "gcp-cs-jwt"}
	}, "test", policy) || loads != 2 || posts != 2 {
		t.Fatalf("registration did not recover: loads=%d posts=%d", loads, posts)
	}
}

func TestBootRegistrationCancellationLeavesGateClosed(t *testing.T) {
	for _, missing := range []BootRegistrationEvidence{{}, {Attestation: "no-kind"}, {AttestationKind: "no-document"}} {
		ctx, cancel := context.WithCancel(t.Context())
		signer, err := receipt.NewSigner()
		if err != nil {
			t.Fatal(err)
		}
		client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Error("incomplete evidence must not be posted")
			return nil, errors.New("unexpected request")
		})})
		client.ConfigureSpendLeaseShadow(signer, nil)
		waits := 0
		policy := bootRegistrationRetryPolicy()
		policy.sleep = func(ctx context.Context, delay time.Duration) error {
			waits++
			if delay < time.Second || delay > time.Minute {
				t.Fatalf("retry delay = %v", delay)
			}
			if waits == 40 {
				cancel()
				return ctx.Err()
			}
			return nil
		}
		if client.registerAttestedBoot(ctx, signer, func() BootRegistrationEvidence { return missing }, "test", policy) {
			t.Fatal("unverified boot was accepted")
		}
		if waits != 40 || client.spendLease.state.Registered() {
			t.Fatal("cancellation changed registration authority")
		}
		if client.registerAttestedBoot(ctx, signer, func() BootRegistrationEvidence {
			t.Error("canceled worker reloaded evidence")
			return missing
		}, "test", policy) {
			t.Fatal("canceled worker registered")
		}
		cancel()
	}
}

func TestStageDBootRegistrationRecoversAfterInitialMintFailure(t *testing.T) {
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	registered := make(chan struct{}, 1)
	client := New("http://127.0.0.1:18080", "internal", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		registered <- struct{}{}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: request, Body: io.NopCloser(strings.NewReader(`{"data":{"verified":true}}`))}, nil
	})})
	var loads atomic.Int32
	client.StartStageDBootRegistration(t.Context(), signer, func() BootRegistrationEvidence {
		if loads.Add(1) == 1 {
			return BootRegistrationEvidence{}
		}
		return BootRegistrationEvidence{Attestation: "recovered", AttestationKind: "gcp-cs-jwt"}
	})
	select {
	case <-registered:
	case <-time.After(6 * time.Second):
		t.Fatal("initial mint failure permanently disabled boot registration")
	}
}
