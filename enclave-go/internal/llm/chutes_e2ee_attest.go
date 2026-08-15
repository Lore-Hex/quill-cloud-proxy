package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	chutesEvidenceMaxBytes = 16 << 20
	chutesProofLifetime    = 2 * time.Minute
)

type chutesEvidenceEnvelope struct {
	ChuteID   string          `json:"chute_id"`
	Instance  string          `json:"instance_id"`
	Nonce     string          `json:"nonce"`
	E2EPubkey string          `json:"e2e_pubkey"`
	Evidence  json.RawMessage `json:"evidence"`
}

type chutesVerificationResult struct {
	VerifiedAt time.Time `json:"verified_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Policy     string    `json:"policy"`
}

func chutesSidecarHTTPClient() *http.Client {
	dialer := func(_ context.Context, _, _ string) (net.Conn, error) {
		c, err := net.DialTimeout("unix", tinfoilSidecarSocket, 2*time.Second)
		if err != nil {
			return nil, err
		}
		if expected := int(expectedSidecarPID.Load()); expected != 0 {
			pid, perr := peerPID(c)
			if perr != nil {
				if !strings.Contains(perr.Error(), "only supported on Linux") {
					_ = c.Close()
					return nil, fmt.Errorf("peercred lookup failed: %w", perr)
				}
			} else if pid != expected {
				_ = c.Close()
				return nil, fmt.Errorf("%w: got pid=%d expected=%d", errSidecarPIDMismatch, pid, expected)
			}
		}
		return c, nil
	}
	return &http.Client{
		Timeout: 3 * time.Minute,
		Transport: &http.Transport{
			DialContext:           dialer,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 150 * time.Second,
		},
	}
}

func verifyChutesEvidenceWithSidecar(
	ctx context.Context,
	envelope *chutesEvidenceEnvelope,
) (*chutesVerificationResult, error) {
	if envelope == nil || strings.TrimSpace(envelope.Instance) == "" ||
		strings.TrimSpace(envelope.Nonce) == "" || strings.TrimSpace(envelope.E2EPubkey) == "" ||
		len(envelope.Evidence) == 0 {
		return nil, errors.New("chutes e2ee: incomplete attestation evidence")
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: marshal attestation evidence: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://attest-sidecar/verify-chutes",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := chutesSidecarHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("chutes e2ee: attestation sidecar unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf(
			"chutes e2ee: attestation refused (HTTP %d): %s",
			resp.StatusCode,
			strings.TrimSpace(string(detail)),
		)
	}
	var result chutesVerificationResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&result); err != nil {
		return nil, fmt.Errorf("chutes e2ee: decode attestation result: %w", err)
	}
	now := time.Now()
	if result.VerifiedAt.IsZero() || result.VerifiedAt.After(now.Add(30*time.Second)) {
		return nil, errors.New("chutes e2ee: sidecar returned invalid verification time")
	}
	if !result.ExpiresAt.After(now) || result.ExpiresAt.After(result.VerifiedAt.Add(chutesProofLifetime+30*time.Second)) {
		return nil, errors.New("chutes e2ee: sidecar returned invalid proof expiry")
	}
	if result.Policy != "chutes-tdx-nvidia-e2e-v1" {
		return nil, errors.New("chutes e2ee: sidecar returned an unexpected verification policy")
	}
	return &result, nil
}
