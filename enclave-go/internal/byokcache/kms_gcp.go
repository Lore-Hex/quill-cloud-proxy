package byokcache

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultKMSEndpoint           = "https://cloudkms.googleapis.com"
	defaultMetadataTokenEndpoint = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- metadata URL, not a secret.
	gcpJWTTokenEndpoint          = "https://oauth2.googleapis.com/token"
	gcpKMSScope                  = "https://www.googleapis.com/auth/cloudkms"
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

	// Cross-cloud path first when GOOGLE_APPLICATION_CREDENTIALS is set.
	// The AWS-side enclave bootstrap writes the SA-key JSON to a tmpfs
	// path and exports the env var; metadata.google.internal doesn't
	// resolve there. Same fallback pattern as the gcscache token
	// source — see enclavetls/gcscache.go::tokenFromSAKey.
	if credPath := strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")); credPath != "" {
		tok, exp, err := s.tokenFromSAKey(ctx, credPath, now)
		if err != nil {
			return "", fmt.Errorf("byokcache: SA-key token: %w", err)
		}
		s.token = tok
		s.expiry = exp
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

// tokenFromSAKey signs a JWT with the service-account RSA key and
// exchanges it at oauth2.googleapis.com for a cloudkms.googleapis.com
// access token. Same flow as enclavetls/gcscache.go but scoped to
// cloudkms instead of devstorage. AWS-side enclave only — the GCP
// metadata path is the primary, this is the cross-cloud fallback.
func (s *MetadataTokenSource) tokenFromSAKey(ctx context.Context, credPath string, now time.Time) (string, time.Time, error) {
	raw, err := os.ReadFile(credPath) // #nosec G304 — path comes from bootstrap config, not user input.
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read sa-key: %w", err)
	}
	var sa struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(raw, &sa); err != nil {
		return "", time.Time{}, fmt.Errorf("parse sa-key json: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return "", time.Time{}, errors.New("sa-key: missing client_email or private_key")
	}
	if sa.Type != "service_account" {
		return "", time.Time{}, fmt.Errorf("sa-key type %q (want service_account)", sa.Type)
	}

	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return "", time.Time{}, errors.New("sa-key: no PEM block")
	}
	var rsaKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr != nil {
			return "", time.Time{}, fmt.Errorf("parse pkcs8: %w", perr)
		}
		var ok bool
		rsaKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return "", time.Time{}, fmt.Errorf("sa-key not RSA (type %T)", key)
		}
	default:
		return "", time.Time{}, fmt.Errorf("unknown PEM type %q", block.Type)
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse pkcs1: %w", err)
	}

	tokenURI := sa.TokenURI
	if tokenURI == "" {
		tokenURI = gcpJWTTokenEndpoint
	}

	hdr := `{"alg":"RS256","typ":"JWT"}`
	claim := fmt.Sprintf(
		`{"iss":%q,"scope":%q,"aud":%q,"exp":%d,"iat":%d}`,
		sa.ClientEmail, gcpKMSScope, tokenURI, now.Add(time.Hour).Unix(), now.Unix(),
	)
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(hdr)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(claim))
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("rsa sign: %w", err)
	}
	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpc.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("jwt exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", time.Time{}, fmt.Errorf("jwt exchange status %d body=%s", resp.StatusCode, body)
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return "", time.Time{}, fmt.Errorf("token decode: %w", err)
	}
	if t.AccessToken == "" {
		return "", time.Time{}, errors.New("jwt exchange: empty access_token")
	}
	if t.ExpiresIn <= 0 {
		t.ExpiresIn = 60
	}
	return t.AccessToken, now.Add(time.Duration(t.ExpiresIn) * time.Second), nil
}

func httpClient(httpc *http.Client) *http.Client {
	if httpc != nil {
		return httpc
	}
	return &http.Client{Timeout: 30 * time.Second}
}
