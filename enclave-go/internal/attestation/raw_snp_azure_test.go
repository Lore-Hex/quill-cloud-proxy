//go:build cloud_azure

package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type snpRoundTrip func(*http.Request) (*http.Response, error)

func (f snpRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRawSNPReportContext(t *testing.T) {
	leaf := []byte("test DER")
	nonce, exporter := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)
	h := sha256.Sum256(leaf)
	expected := bytes.Join([][]byte{[]byte("trustedrouter/azure-snp/session/v1\x00"), h[:], nonce, exporter}, nil)
	report := make([]byte, snpReportSize)
	binding := sha256.Sum256(expected)
	copy(report[0x50:], binding[:])
	valid := `{"report":"` + hex.EncodeToString(report) + `"}`
	old := rawSNPClient
	t.Cleanup(func() { rawSNPClient = old })
	for _, tc := range []struct {
		name, body string
		code       int
		ok         bool
	}{
		{"good", valid, 200, true}, {"truncated", `{"report":"00"}`, 200, false},
		{"other session", `{"report":"` + strings.Repeat("00", snpReportSize) + `"}`, 200, false},
		{"oversize", valid + strings.Repeat(" ", 4096), 200, false}, {"wrong format", "jwt", 200, false},
		{"redirect", "", 302, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rawSNPClient = &http.Client{Transport: snpRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "http://127.0.0.1:8080/attest/raw" || r.Method != "POST" {
					t.Fatal("unexpected sidecar request")
				}
				var in struct {
					RuntimeData []byte `json:"runtime_data"`
				}
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !bytes.Equal(in.RuntimeData, expected) {
					t.Fatal("wrong runtime_data preimage")
				}
				return &http.Response{StatusCode: tc.code, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})}
			out, err := GetRawSNP(t.Context(), leaf, nonce, exporter)
			if tc.ok != (err == nil) || (tc.ok && !bytes.Equal(out, report)) {
				t.Fatalf("result length=%d err=%v", len(out), err)
			}
		})
	}
	if _, err := GetRawSNP(context.Background(), leaf, exporter, exporter); err == nil {
		t.Fatal("accepted identical challenge and exporter")
	}
	rawSNPSlot <- struct{}{}
	defer func() { <-rawSNPSlot }()
	if _, err := GetRawSNP(context.Background(), leaf, nonce, exporter); err != ErrIssuerUnavailable {
		t.Fatalf("busy issuer: %v", err)
	}
}
