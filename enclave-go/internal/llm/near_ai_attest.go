package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const nearAIProofLifetime = 2 * time.Minute

type nearAIEvidenceEnvelope struct {
	Model          string          `json:"model"`
	Domain         string          `json:"domain"`
	Nonce          string          `json:"nonce"`
	TLSFingerprint string          `json:"tls_fingerprint"`
	Evidence       json.RawMessage `json:"evidence"`
}

type nearAIVerificationResult struct {
	VerifiedAt time.Time `json:"verified_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Policy     string    `json:"policy"`
}

func verifyNearAIEvidenceWithSidecar(
	ctx context.Context,
	envelope *nearAIEvidenceEnvelope,
) (*nearAIVerificationResult, error) {
	if envelope == nil || strings.TrimSpace(envelope.Model) == "" ||
		strings.TrimSpace(envelope.Domain) == "" || strings.TrimSpace(envelope.Nonce) == "" ||
		strings.TrimSpace(envelope.TLSFingerprint) == "" || len(envelope.Evidence) == 0 {
		return nil, errors.New("near-ai: incomplete attestation evidence")
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("near-ai: marshal attestation evidence: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://attest-sidecar/verify-near-ai",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := chutesSidecarHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("near-ai: attestation sidecar unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf(
			"near-ai: attestation refused (HTTP %d): %s",
			resp.StatusCode,
			strings.TrimSpace(string(detail)),
		)
	}
	var result nearAIVerificationResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&result); err != nil {
		return nil, fmt.Errorf("near-ai: decode attestation result: %w", err)
	}
	now := time.Now()
	if result.VerifiedAt.IsZero() || result.VerifiedAt.After(now.Add(30*time.Second)) {
		return nil, errors.New("near-ai: sidecar returned invalid verification time")
	}
	if !result.ExpiresAt.After(now) || result.ExpiresAt.After(result.VerifiedAt.Add(nearAIProofLifetime+30*time.Second)) {
		return nil, errors.New("near-ai: sidecar returned invalid proof expiry")
	}
	if result.Policy != "near-ai-tdx-nvidia-direct-v1" {
		return nil, errors.New("near-ai: sidecar returned an unexpected verification policy")
	}
	return &result, nil
}
