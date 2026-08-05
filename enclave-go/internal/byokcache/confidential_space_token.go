//go:build cloud_gcp

package byokcache

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
)

const (
	confidentialSpaceSTSAudience = "https://sts.googleapis.com"
	defaultSTSEndpoint           = "https://sts.googleapis.com/v1/token"
	cloudPlatformScope           = "https://www.googleapis.com/auth/cloud-platform"
)

// ConfidentialSpaceTokenSource exchanges a launcher-minted attestation JWT
// for a federated Google access token. The workload identity provider can then
// gate GCS/KMS access on production Confidential Space and the exact container
// image digest instead of trusting the VM's ordinary service account.
type ConfidentialSpaceTokenSource struct {
	ProviderAudience string
	HTTPClient       *http.Client
	STSEndpoint      string
	Now              func() time.Time
	MintToken        func(context.Context, string) ([]byte, error)

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func NewConfidentialSpaceTokenSource(providerAudience string, httpc *http.Client) (*ConfidentialSpaceTokenSource, error) {
	providerAudience = strings.TrimSpace(providerAudience)
	if !strings.HasPrefix(providerAudience, "//iam.googleapis.com/projects/") || !strings.Contains(providerAudience, "/workloadIdentityPools/") || !strings.Contains(providerAudience, "/providers/") {
		return nil, fmt.Errorf("confidential identity: invalid workload identity provider audience")
	}
	if httpc == nil {
		httpc = &http.Client{Timeout: 15 * time.Second}
	}
	return &ConfidentialSpaceTokenSource{
		ProviderAudience: providerAudience,
		HTTPClient:       httpc,
		STSEndpoint:      defaultSTSEndpoint,
		Now:              time.Now,
		MintToken:        attestation.MintOIDCToken,
	}, nil
}

func (s *ConfidentialSpaceTokenSource) Token(ctx context.Context) (string, error) {
	if s == nil {
		return "", fmt.Errorf("confidential identity: nil token source")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	if s.token != "" && now.Before(s.expiresAt.Add(-30*time.Second)) {
		return s.token, nil
	}
	attestationToken, err := s.MintToken(ctx, confidentialSpaceSTSAudience)
	if err != nil {
		return "", fmt.Errorf("confidential identity: mint attestation token: %w", err)
	}
	values := url.Values{
		"audience":             {s.ProviderAudience},
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":                {cloudPlatformScope},
		"subject_token":        {string(attestationToken)},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
	}
	endpoint := strings.TrimSpace(s.STSEndpoint)
	if endpoint == "" {
		endpoint = defaultSTSEndpoint
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := httpClient(s.HTTPClient).Do(request)
	if err != nil {
		return "", fmt.Errorf("confidential identity: STS exchange: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("confidential identity: STS http %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return "", fmt.Errorf("confidential identity: decode STS response: %w", err)
	}
	if decoded.AccessToken == "" || (decoded.TokenType != "" && !strings.EqualFold(decoded.TokenType, "Bearer")) {
		return "", fmt.Errorf("confidential identity: invalid STS response")
	}
	if decoded.ExpiresIn <= 0 {
		decoded.ExpiresIn = 60
	}
	s.token = decoded.AccessToken
	s.expiresAt = now.Add(time.Duration(decoded.ExpiresIn) * time.Second)
	return s.token, nil
}
