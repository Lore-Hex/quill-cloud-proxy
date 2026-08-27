package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
)

func TestReceiptKeyRouteServesStableEnvelope(t *testing.T) {
	resetReceiptTestState(t)
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	receiptSigner = signer
	attestationDocument := []byte("header.payload.signature")
	if attestation.Kind == "aws-nitro-cose" {
		attestationDocument = []byte{0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26}
	}
	switch attestation.Kind {
	case "gcp-cs-jwt", "aws-nitro-cose", "azure-maa-jwt":
	default:
		t.Fatalf("unexpected compiled attestation kind %q", attestation.Kind)
	}
	receiptAttestationCache.Store(&cachedReceiptAttestation{
		document: append([]byte(nil), attestationDocument...),
		kind:     attestation.Kind,
	})

	request := func() (*http.Response, []byte) {
		t.Helper()
		conn := newScriptedConn("GET /receipt-key HTTP/1.1\r\nHost: test\r\n\r\n", nil)
		serveOne(context.Background(), conn, nil, nil, nil, []byte("devices"), nil, nil)
		return readRawHTTPResponse(t, conn.writes.Bytes())
	}
	resp, body := request()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if bytes.Contains(body, []byte{'\n'}) {
		t.Fatalf("envelope contains LF: %q", body)
	}

	var envelope receiptKeyEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if envelope.JWK.KeyType != "OKP" || envelope.JWK.Curve != "Ed25519" {
		t.Fatalf("jwk = %#v", envelope.JWK)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(envelope.JWK.X)
	if err != nil {
		t.Fatalf("decode jwk.x: %v", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("decoded jwk.x length = %d, want %d", len(publicKey), ed25519.PublicKeySize)
	}
	digest := sha256.Sum256(publicKey)
	if want := base64.RawURLEncoding.EncodeToString(digest[:]); envelope.KID != want {
		t.Fatalf("kid = %q, want SHA-256(jwk.x) %q", envelope.KID, want)
	}
	if envelope.KID != signer.Kid() {
		t.Fatalf("kid = %q, want signer kid %q", envelope.KID, signer.Kid())
	}
	wantAttestation := string(attestationDocument)
	if attestation.Kind == "aws-nitro-cose" {
		wantAttestation = base64.RawURLEncoding.EncodeToString(attestationDocument)
	}
	if envelope.Attestation != wantAttestation {
		t.Fatalf("att = %q, want %q", envelope.Attestation, wantAttestation)
	}
	if envelope.AttestationKind != attestation.Kind {
		t.Fatalf("att_kind = %q, want compiled kind %q", envelope.AttestationKind, attestation.Kind)
	}
	flattened, err := signer.SignFlattened(receipt.Claims{}, attestationDocument, attestation.Kind)
	if err != nil {
		t.Fatalf("SignFlattened: %v", err)
	}
	var flattenedEnvelope struct {
		Protected string `json:"protected"`
	}
	if err := json.Unmarshal(flattened, &flattenedEnvelope); err != nil {
		t.Fatalf("unmarshal flattened receipt: %v", err)
	}
	protectedJSON, err := base64.RawURLEncoding.DecodeString(flattenedEnvelope.Protected)
	if err != nil {
		t.Fatalf("decode flattened protected header: %v", err)
	}
	var protectedHeader struct {
		Attestation     string `json:"att"`
		AttestationKind string `json:"att_kind"`
	}
	if err := json.Unmarshal(protectedJSON, &protectedHeader); err != nil {
		t.Fatalf("unmarshal flattened protected header: %v", err)
	}
	if envelope.Attestation != protectedHeader.Attestation || envelope.AttestationKind != protectedHeader.AttestationKind {
		t.Fatalf("receipt-key attestation (%q, %q) differs from flattened header (%q, %q)", envelope.Attestation, envelope.AttestationKind, protectedHeader.Attestation, protectedHeader.AttestationKind)
	}
	wantBody := []byte(`{"kid":"` + envelope.KID + `","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + envelope.JWK.X + `"},"att":"` + envelope.Attestation + `","att_kind":"` + envelope.AttestationKind + `"}`)
	if !bytes.Equal(body, wantBody) {
		t.Fatalf("body field order or encoding changed:\n got %s\nwant %s", body, wantBody)
	}

	secondResp, secondBody := request()
	if secondResp.StatusCode != http.StatusOK {
		t.Fatalf("second status = %d body=%s", secondResp.StatusCode, secondBody)
	}
	if !bytes.Equal(body, secondBody) {
		t.Fatalf("envelope is not byte-stable:\nfirst  %s\nsecond %s", body, secondBody)
	}
}

func TestReceiptAttestationRouteServesCachedDocument(t *testing.T) {
	resetReceiptTestState(t)
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	receiptSigner = signer
	wantDocument := []byte("cached-key-binding-document")
	receiptAttestationCache.Store(&cachedReceiptAttestation{
		document: append([]byte(nil), wantDocument...),
		kind:     attestation.Kind,
	})

	conn := newScriptedConn("GET /receipt-attestation HTTP/1.1\r\nHost: test\r\n\r\n", nil)
	serveOne(context.Background(), conn, nil, nil, nil, []byte("devices"), nil, nil)
	resp, body := readRawHTTPResponse(t, conn.writes.Bytes())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if !bytes.Equal(body, wantDocument) {
		t.Fatalf("body = %q, want cached document %q", body, wantDocument)
	}
	wantContentType := map[string]string{
		"gcp-cs-jwt":     "application/jwt",
		"azure-maa-jwt":  "application/jwt",
		"aws-nitro-cose": "application/cbor",
	}[attestation.Kind]
	if got := resp.Header.Get("Content-Type"); got != wantContentType {
		t.Fatalf("Content-Type = %q, want %q for %q", got, wantContentType, attestation.Kind)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := resp.Header.Get("x-receipt-att-kind"); got != attestation.Kind {
		t.Fatalf("x-receipt-att-kind = %q, want %q", got, attestation.Kind)
	}
}

func TestReceiptAttestationContentTypePerKind(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want string
	}{
		{kind: "gcp-cs-jwt", want: "application/jwt"},
		{kind: "azure-maa-jwt", want: "application/jwt"},
		{kind: "aws-nitro-cose", want: "application/cbor"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			if got := receiptAttestationContentType(tc.kind); got != tc.want {
				t.Fatalf("content type = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReceiptsOffReturns404AndKeepsLiveAttestationLegacyShaped(t *testing.T) {
	resetReceiptTestState(t)
	t.Setenv("QUILL_RECEIPTS", "off")
	oldGetAttestation := getAttestation
	defer func() { getAttestation = oldGetAttestation }()
	getAttestation = func(_, _, _, _, _ []byte) ([]byte, error) {
		t.Fatal("disabled receipt initialization must not mint an attestation")
		return nil, nil
	}
	if err := initializeReceiptSigner(t.Context(), nil, []byte("devices")); err != nil {
		t.Fatalf("initializeReceiptSigner: %v", err)
	}
	if receiptSigner != nil || receiptAttestationCache.Load() != nil {
		t.Fatal("QUILL_RECEIPTS=off left receipt state enabled")
	}

	for _, path := range []string{"/receipt-attestation", "/receipt-key"} {
		receiptConn := newScriptedConn("GET "+path+" HTTP/1.1\r\nHost: test\r\n\r\n", nil)
		serveOne(context.Background(), receiptConn, nil, nil, nil, []byte("devices"), nil, nil)
		receiptResp, receiptBody := readRawHTTPResponse(t, receiptConn.writes.Bytes())
		if receiptResp.StatusCode != http.StatusNotFound || !bytes.Contains(receiptBody, []byte(`"message":"route not found"`)) {
			t.Fatalf("disabled %s response status=%d body=%s", path, receiptResp.StatusCode, receiptBody)
		}
	}

	getAttestation = func(_, _, _, channelBinding, receiptKeyFP []byte) ([]byte, error) {
		if receiptKeyFP != nil {
			t.Fatalf("live /attestation receiptKeyFP = %x, want nil", receiptKeyFP)
		}
		if len(channelBinding) != enclavetls.ExporterLength {
			t.Fatalf("channel binding length = %d", len(channelBinding))
		}
		return []byte("legacy-live-attestation"), nil
	}
	liveConn := &attestationExporterConn{
		scriptedConn: newScriptedConn("GET /attestation HTTP/1.1\r\nHost: test\r\n\r\n", []byte("leaf")),
		exporter:     bytes.Repeat([]byte{0x42}, enclavetls.ExporterLength),
	}
	serveOne(context.Background(), liveConn, nil, nil, nil, []byte("devices"), nil, nil)
	liveResp, liveBody := readRawHTTPResponse(t, liveConn.writes.Bytes())
	if liveResp.StatusCode != http.StatusOK || string(liveBody) != "legacy-live-attestation" {
		t.Fatalf("legacy attestation status=%d body=%s", liveResp.StatusCode, liveBody)
	}
}

func TestReceiptKeyRouteReturns503WhenAttestationCacheIsEmpty(t *testing.T) {
	resetReceiptTestState(t)
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	receiptSigner = signer

	conn := newScriptedConn("GET /receipt-key HTTP/1.1\r\nHost: test\r\n\r\n", nil)
	serveOne(context.Background(), conn, nil, nil, nil, []byte("devices"), nil, nil)
	resp, body := readRawHTTPResponse(t, conn.writes.Bytes())
	if resp.StatusCode != http.StatusServiceUnavailable || !bytes.Contains(body, []byte(`"message":"receipt attestation unavailable"`)) {
		t.Fatalf("empty-cache response status=%d body=%s", resp.StatusCode, body)
	}
}

func TestReceiptAttestationReminterSwapsAtomicPointer(t *testing.T) {
	resetReceiptTestState(t)
	oldGetAttestation := getAttestation
	oldInterval := receiptAttestationRemintInterval
	defer func() {
		getAttestation = oldGetAttestation
		receiptAttestationRemintInterval = oldInterval
	}()

	initial := &cachedReceiptAttestation{document: []byte("old"), kind: attestation.Kind}
	receiptAttestationCache.Store(initial)
	var calls atomic.Int32
	getAttestation = func(_, _, nonce, channelBinding, receiptKeyFP []byte) ([]byte, error) {
		if nonce != nil || channelBinding != nil {
			t.Fatalf("key-binding remint included nonce=%x exporter=%x", nonce, channelBinding)
		}
		if len(receiptKeyFP) != 32 {
			t.Fatalf("receipt key fingerprint length = %d", len(receiptKeyFP))
		}
		calls.Add(1)
		return []byte("new"), nil
	}
	receiptAttestationRemintInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runReceiptAttestationReminter(ctx, nil, []byte("devices"), [32]byte{1}, &bytes.Buffer{})
	}()

	deadline := time.Now().Add(time.Second)
	for receiptAttestationCache.Load() == initial && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	got := receiptAttestationCache.Load()
	if got == initial || got == nil || string(got.document) != "new" {
		t.Fatalf("cache = %#v, want a newly stored document", got)
	}
	if calls.Load() == 0 {
		t.Fatal("reminter did not mint")
	}
}

func TestReceiptAttestationMintFailureKeepsLastGood(t *testing.T) {
	resetReceiptTestState(t)
	oldGetAttestation := getAttestation
	defer func() { getAttestation = oldGetAttestation }()
	lastGood := &cachedReceiptAttestation{document: []byte("last-good"), kind: attestation.Kind}
	receiptAttestationCache.Store(lastGood)
	getAttestation = func(_, _, _, _, _ []byte) ([]byte, error) {
		return nil, errors.New("issuer unavailable")
	}
	if err := remintReceiptAttestation(nil, []byte("devices"), bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("remintReceiptAttestation returned nil error")
	}
	if got := receiptAttestationCache.Load(); got != lastGood {
		t.Fatalf("failed remint replaced last-good pointer: got %#v want %#v", got, lastGood)
	}
}

func TestConfiguredReceiptIssuerUsesExplicitCanonicalOrigin(t *testing.T) {
	resetReceiptTestState(t)
	t.Setenv("QUILL_RECEIPT_ISS", "https://api-aws.trustedrouter.com/")
	issuer, err := configuredReceiptIssuer([]string{"api.quillrouter.com,api.trustedrouter.com"})
	if err != nil || issuer != "https://api-aws.trustedrouter.com" {
		t.Fatalf("issuer=%q err=%v", issuer, err)
	}
	t.Setenv("QUILL_RECEIPT_ISS", "https://api.trustedrouter.com/path")
	if _, err := configuredReceiptIssuer(nil); err == nil {
		t.Fatal("issuer with a path was accepted")
	}
}

func resetReceiptTestState(t *testing.T) {
	t.Helper()
	oldSigner := receiptSigner
	oldCached := receiptAttestationCache.Load()
	oldIssuer := receiptIssuer
	receiptSigner = nil
	receiptAttestationCache.Store(nil)
	receiptIssuer = "https://api.trustedrouter.com"
	t.Cleanup(func() {
		receiptSigner = oldSigner
		receiptAttestationCache.Store(oldCached)
		receiptIssuer = oldIssuer
	})
}

func readRawHTTPResponse(t *testing.T, raw []byte) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v; raw=%s", err, raw)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp, body
}
