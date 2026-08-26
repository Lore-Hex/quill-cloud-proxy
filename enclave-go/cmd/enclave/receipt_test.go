package main

import (
	"bufio"
	"bytes"
	"context"
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
	if got := resp.Header.Get("Content-Type"); got != "application/cbor" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := resp.Header.Get("x-receipt-att-kind"); got != attestation.Kind {
		t.Fatalf("x-receipt-att-kind = %q, want %q", got, attestation.Kind)
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

	receiptConn := newScriptedConn("GET /receipt-attestation HTTP/1.1\r\nHost: test\r\n\r\n", nil)
	serveOne(context.Background(), receiptConn, nil, nil, nil, []byte("devices"), nil, nil)
	receiptResp, receiptBody := readRawHTTPResponse(t, receiptConn.writes.Bytes())
	if receiptResp.StatusCode != http.StatusNotFound || !bytes.Contains(receiptBody, []byte(`"message":"route not found"`)) {
		t.Fatalf("disabled response status=%d body=%s", receiptResp.StatusCode, receiptBody)
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

func resetReceiptTestState(t *testing.T) {
	t.Helper()
	oldSigner := receiptSigner
	oldCached := receiptAttestationCache.Load()
	receiptSigner = nil
	receiptAttestationCache.Store(nil)
	t.Cleanup(func() {
		receiptSigner = oldSigner
		receiptAttestationCache.Store(oldCached)
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
