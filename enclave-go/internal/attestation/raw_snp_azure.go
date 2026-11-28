//go:build cloud_azure

package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

const snpReportSize = 1184

var rawSNPClient = &http.Client{
	Timeout:       5 * time.Second,
	Transport:     &http.Transport{Proxy: nil, MaxConnsPerHost: 1},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}
var rawSNPSlot = make(chan struct{}, 1)

// GetRawSNP returns evidence, not a verification verdict. Only a relying party
// with independently chosen AMD roots, measurements and TCB policy can verify it.
func GetRawSNP(ctx context.Context, leaf, nonce, exporter []byte) ([]byte, error) {
	if len(leaf) == 0 || len(nonce) != 32 || len(exporter) != 32 || bytes.Equal(nonce, exporter) {
		return nil, errors.New("invalid raw SNP bindings")
	}
	select {
	case rawSNPSlot <- struct{}{}:
		defer func() { <-rawSNPSlot }()
	default:
		return nil, ErrIssuerUnavailable
	}
	leafHash := sha256.Sum256(leaf)
	preimage := append([]byte("trustedrouter/azure-snp/session/v1\x00"), leafHash[:]...)
	preimage = append(preimage, nonce...)
	preimage = append(preimage, exporter...)
	return requestRawSNP(ctx, rawSNPClient, preimage)
}

func requestRawSNP(ctx context.Context, client *http.Client, preimage []byte) ([]byte, error) {
	body, err := json.Marshal(struct {
		RuntimeData []byte `json:"runtime_data"`
	}{preimage})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1:8080/attest/raw", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrIssuerUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrIssuerUnavailable
	}
	const limit = 4096
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	var envelope struct {
		Report string `json:"report"`
	}
	if err != nil || len(b) > limit || json.Unmarshal(b, &envelope) != nil || len(envelope.Report) != 2*snpReportSize {
		return nil, ErrIssuerUnavailable
	}
	report, err := hex.DecodeString(envelope.Report)
	var expected [64]byte
	h := sha256.Sum256(preimage)
	copy(expected[:], h[:])
	// REPORT_DATA is fixed by the SEV-SNP ABI. Reject stale/differently bound
	// responses locally too; this check is not a substitute for AMD's signature.
	if err != nil || !bytes.Equal(report[0x50:0x90], expected[:]) {
		return nil, ErrIssuerUnavailable
	}
	return report, nil
}
