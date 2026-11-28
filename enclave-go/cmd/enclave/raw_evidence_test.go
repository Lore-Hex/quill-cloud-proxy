package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
)

func TestRequestedHardwareEvidenceNeverDowngrades(t *testing.T) {
	old, oldRaw := getAttestation, getRawSNP
	t.Cleanup(func() { getAttestation, getRawSNP = old, oldRaw })
	getAttestation = func(context.Context, []byte, []byte, []byte, []byte, []byte) ([]byte, error) {
		t.Fatal("unexpected JWT fallback")
		return nil, nil
	}
	nonce, exporter := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	want := 200
	if attestation.Kind != "azure-maa-jwt" {
		want = 406
	}
	for _, tc := range []struct {
		query  string
		status int
	}{
		{"format=amd-snp-v1", want}, {"format=other", 406}, {"format=", 406}, {"format=amd-snp-v1&format=amd-snp-v1", 406}, {"format=%GG", 400},
	} {
		var b bytes.Buffer
		getRawSNP = func(_ context.Context, leaf, n, e []byte) ([]byte, error) {
			if string(leaf) != "leaf" || !bytes.Equal(n, nonce) || !bytes.Equal(e, exporter) {
				t.Fatal("not the connection's exact bindings")
			}
			return []byte("raw evidence"), nil
		}
		serveRequestedAttestation(t.Context(), &b, "/attestation?"+tc.query, []byte("leaf"), nil, nonce, exporter)
		r, body := readRawHTTPResponse(t, b.Bytes())
		if r.StatusCode != tc.status {
			t.Fatalf("%s: %d", tc.query, r.StatusCode)
		}
		if r.StatusCode == http.StatusOK && (string(body) != "raw evidence" || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Content-Type") != "application/vnd.trustedrouter.amd-snp-report") {
			t.Fatal("incorrect evidence response")
		}
	}
	if attestation.Kind == "azure-maa-jwt" {
		getRawSNP = func(context.Context, []byte, []byte, []byte) ([]byte, error) {
			return nil, errors.New("sensitive test diagnostic")
		}
		for _, tc := range []struct {
			nonce, exporter []byte
			status          int
		}{{nil, exporter, 400}, {exporter, exporter, 400}, {nonce, nil, 503}, {nonce, exporter, 503}} {
			var b bytes.Buffer
			serveRequestedAttestation(t.Context(), &b, "/attestation?format=amd-snp-v1", []byte("leaf"), nil, tc.nonce, tc.exporter)
			r, body := readRawHTTPResponse(t, b.Bytes())
			if r.StatusCode != tc.status || bytes.Contains(body, []byte("sensitive test diagnostic")) {
				t.Fatalf("wrong error: %d", r.StatusCode)
			}
		}
	}
}
