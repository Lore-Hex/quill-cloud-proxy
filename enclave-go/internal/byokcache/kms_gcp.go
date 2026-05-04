package byokcache

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultKMSEndpoint           = "https://cloudkms.googleapis.com"
	defaultMetadataTokenEndpoint = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- metadata URL, not a secret.
)

type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

type GoogleKMSUnwrapper struct {
	HTTPClient  *http.Client
	TokenSource TokenSource
	Endpoint    string
}

func (u *GoogleKMSUnwrapper) UnwrapDEK(ctx context.Context, keyName string, encryptedDEK, aad []byte) ([]byte, error) {
	if strings.TrimSpace(keyName) == "" {
		return nil, fmt.Errorf("kms: empty key name")
	}
	tokenSource := u.TokenSource
	if tokenSource == nil {
		tokenSource = NewMetadataTokenSource(nil)
	}
	token, err := tokenSource.Token(ctx)
	if err != nil {
		return nil, err
	}

	payload := map[string]string{
		"ciphertext":                  base64.StdEncoding.EncodeToString(encryptedDEK),
		"additionalAuthenticatedData": base64.StdEncoding.EncodeToString(aad),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(u.Endpoint, "/")
	if endpoint == "" {
		endpoint = defaultKMSEndpoint
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint+"/v1/"+keyName+":decrypt",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient(u.HTTPClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("kms decrypt: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("kms decrypt: read error body: %w", readErr)
		}
		return nil, fmt.Errorf("kms decrypt http %d: %s", resp.StatusCode, errBody)
	}

	var decoded struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("kms decrypt: decode response: %w", err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(decoded.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("kms decrypt: decode plaintext: %w", err)
	}
	return plaintext, nil
}

type MetadataTokenSource struct {
	httpc    *http.Client
	endpoint string
	now      func() time.Time

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func NewMetadataTokenSource(httpc *http.Client) *MetadataTokenSource {
	return &MetadataTokenSource{
		httpc:    httpClient(httpc),
		endpoint: defaultMetadataTokenEndpoint,
		now:      time.Now,
	}
}

func (s *MetadataTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.token != "" && now.Before(s.expiry.Add(-30*time.Second)) {
		return s.token, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := s.httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", fmt.Errorf("metadata token: read error body: %w", readErr)
		}
		return "", fmt.Errorf("metadata token http %d: %s", resp.StatusCode, errBody)
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", fmt.Errorf("metadata token: decode response: %w", err)
	}
	if decoded.AccessToken == "" {
		return "", fmt.Errorf("metadata token: empty access token")
	}
	if decoded.ExpiresIn <= 0 {
		decoded.ExpiresIn = 60
	}
	s.token = decoded.AccessToken
	s.expiry = now.Add(time.Duration(decoded.ExpiresIn) * time.Second)
	return s.token, nil
}

func httpClient(httpc *http.Client) *http.Client {
	if httpc != nil {
		return httpc
	}
	return &http.Client{Timeout: 30 * time.Second}
}
