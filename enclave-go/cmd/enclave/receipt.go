package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
)

var receiptSigner *receipt.Signer
var receiptIssuer = "https://api.trustedrouter.com"

type cachedReceiptAttestation struct {
	document []byte
	kind     string
}

// receiptKeyEnvelope declaration order is the fixed JSON wire order.
type receiptKeyEnvelope struct {
	KID             string      `json:"kid"`
	JWK             receipt.JWK `json:"jwk"`
	Attestation     string      `json:"att"`
	AttestationKind string      `json:"att_kind"`
}

var receiptAttestationCache atomic.Pointer[cachedReceiptAttestation]

// A duration seam keeps the background lifecycle testable without waiting for
// production's half-hour refresh cadence. Each actual wait is jittered by 10%.
var receiptAttestationRemintInterval = 30 * time.Minute

// initializeReceiptSigner runs only after entropy seeding and TLS setup. A
// disabled receipt subsystem leaves both the signer and cache nil so all
// existing attestation calls retain their legacy shape.
func initializeReceiptSigner(ctx context.Context, tlsServer *enclavetls.Server, deviceBlob []byte, apiHosts ...string) error {
	receiptAttestationCache.Store(nil)
	if strings.EqualFold(strings.TrimSpace(os.Getenv("QUILL_RECEIPTS")), "off") {
		receiptSigner = nil
		return nil
	}
	issuer, err := configuredReceiptIssuer(apiHosts)
	if err != nil {
		return err
	}
	receiptIssuer = issuer

	signer, err := receipt.NewSigner()
	if err != nil {
		return err
	}
	receiptSigner = signer
	commitment := signer.KeyCommitment()
	leafDER := currentReceiptLeafDER(tlsServer)
	if err := remintReceiptAttestation(leafDER, deviceBlob, commitment[:]); err != nil {
		fmt.Fprintf(os.Stderr, "receipt.attestation_initial_mint_failed err=%q\n", err.Error())
	}
	go runReceiptAttestationReminter(ctx, tlsServer, deviceBlob, commitment, os.Stderr)
	return nil
}

func configuredReceiptIssuer(apiHosts []string) (string, error) {
	issuer := strings.TrimSpace(os.Getenv("QUILL_RECEIPT_ISS"))
	if issuer == "" && len(apiHosts) > 0 {
		host, _, _ := strings.Cut(apiHosts[0], ",")
		host = strings.TrimSpace(host)
		if host != "" {
			issuer = "https://" + host
		}
	}
	if issuer == "" {
		issuer = receiptIssuer
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("receipt: QUILL_RECEIPT_ISS must be a canonical https origin")
	}
	return strings.TrimSuffix(issuer, "/"), nil
}

func currentReceiptLeafDER(tlsServer *enclavetls.Server) []byte {
	if tlsServer == nil {
		return nil
	}
	return tlsServer.CurrentLeafDER()
}

func remintReceiptAttestation(leafDER, deviceBlob, receiptKeyFP []byte) error {
	document, err := getAttestation(leafDER, deviceBlob, nil, nil, receiptKeyFP)
	if err != nil {
		return err
	}
	receiptAttestationCache.Store(&cachedReceiptAttestation{
		document: append([]byte(nil), document...),
		kind:     attestation.Kind,
	})
	return nil
}

func runReceiptAttestationReminter(
	ctx context.Context,
	tlsServer *enclavetls.Server,
	deviceBlob []byte,
	receiptKeyFP [32]byte,
	logWriter io.Writer,
) {
	for {
		timer := time.NewTimer(jitteredReceiptAttestationInterval(receiptAttestationRemintInterval))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := remintReceiptAttestation(currentReceiptLeafDER(tlsServer), deviceBlob, receiptKeyFP[:]); err != nil {
			fmt.Fprintf(logWriter, "receipt.attestation_remint_failed err=%q\n", err.Error())
		}
	}
}

func jitteredReceiptAttestationInterval(base time.Duration) time.Duration {
	if base <= 0 {
		return time.Nanosecond
	}
	span := base / 10
	if span == 0 {
		return base
	}
	randomOffset, err := rand.Int(rand.Reader, big.NewInt(int64(2*span)+1))
	if err != nil {
		return base
	}
	return base - span + time.Duration(randomOffset.Int64())
}

func serveReceiptAttestation(conn io.Writer) bool {
	cached := receiptAttestationCache.Load()
	if cached == nil || len(cached.document) == 0 {
		writeError(conn, 503, "receipt attestation unavailable")
		return false
	}
	fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: %d\r\nCache-Control: no-store\r\nx-receipt-att-kind: %s\r\nConnection: keep-alive\r\n\r\n",
		len(cached.document), cached.kind)
	_, _ = conn.Write(cached.document)
	return true
}

func serveReceiptKey(conn io.Writer) bool {
	cached := receiptAttestationCache.Load()
	if cached == nil || len(cached.document) == 0 {
		writeError(conn, 503, "receipt attestation unavailable")
		return false
	}
	attestationValue, err := receipt.EncodeAttestation(cached.document, cached.kind)
	if err != nil {
		writeError(conn, 503, "receipt attestation unavailable")
		return false
	}
	body, err := json.Marshal(receiptKeyEnvelope{
		KID:             receiptSigner.Kid(),
		JWK:             receiptSigner.JWK(),
		Attestation:     attestationValue,
		AttestationKind: cached.kind,
	})
	if err != nil {
		writeError(conn, 500, "receipt key unavailable")
		return false
	}
	fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n",
		len(body))
	_, _ = conn.Write(body)
	return true
}
