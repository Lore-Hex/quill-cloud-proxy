package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
)

func TestAttestationIssuerUnavailableIsRetryableAndRedacted(t *testing.T) {
	old := getAttestation
	defer func() { getAttestation = old }()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	getAttestation = func(got context.Context, _, _, _, _, _ []byte) ([]byte, error) {
		if got != ctx {
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
