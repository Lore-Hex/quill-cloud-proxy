// Shared autocert.Cache backed by a single GCS bucket so every replica in
// a MIG sees the same ACME account key + challenge tokens + issued certs.
//
// Why this exists: autocert's TLS-ALPN-01 challenge round-trip lands on
// whichever backend the L4 LB forwarded LE's validation TLS handshake to.
// With per-replica in-memory caches, only the replica that *initiated* the
// order has the challenge cert; all other replicas fail the handshake with
// "no token cert", LE marks the challenge invalid, and renewal stalls
// indefinitely. The fix is a cache that every replica can read + write —
// any replica that picks up LE's validation handshake serves the same
// challenge cert. Same idea works for the issued cert too: one replica
// renews, all replicas see the result on next read.
//
// Bucket: gs://quill-acme-cache, single-region us-central1, encrypted at
// rest with KMS key `acme-cache-envelope`. Workload SA holds objectAdmin
// on this bucket only. EU enclaves pay one trans-Atlantic round trip per
// cache op; that's only on cert renewal (~60 day cadence), never per
// request.
//
// Trust property note: CMEK gives "Google contractually doesn't decrypt
// without a court order"; it does NOT give "only the attested PCR0 image
// can decrypt." A future hardening step is to envelope-encrypt cache
// entries with a KMS key locked to the workload's image digest, the way
// the byok-envelope key is. Until then this is the same trust posture as
// our Spanner/Bigtable CMEK setup.
package enclavetls

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

	"golang.org/x/crypto/acme/autocert"
)

const (
	gcsAPIBase    = "https://storage.googleapis.com/storage/v1"
	gcsUploadBase = "https://storage.googleapis.com/upload/storage/v1"
	metadataToken = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- metadata endpoint URL, not a secret.
	gcpTokenURL   = "https://oauth2.googleapis.com/token"                                                        // #nosec G101 -- public OAuth token endpoint, not a credential.
	gcsScope      = "https://www.googleapis.com/auth/devstorage.read_write"
)

// NewGCSCache returns an autocert.Cache backed by GCS. Callers should pass
// the bucket name only (no `gs://` prefix). The workload's GCE SA must
// hold storage.objectAdmin on the bucket, and the bucket should have CMEK
// encryption configured at rest — handled by infra (deploy script /
// terraform), not by this code.
//
// HTTP clients come from newCacheHTTPClient / newTokenHTTPClient which
// are build-tag-specialized:
//   - GCP / dev: stdlib http.Client (default DNS + TCP).
//   - AWS Nitro: vsockhttp.NewClient with the gcsCacheTunnels list
//     (oauth2.googleapis.com + storage.googleapis.com — see
//     gcscache_http_aws.go). Nitro has no NIC; without this the
//     GCS read would block forever / fail DNS.
func NewGCSCache(bucket string) autocert.Cache {
	return &gcsCache{
		bucket:     bucket,
		httpClient: newCacheHTTPClient(),
		tokens:     &gcpTokenSource{httpClient: newTokenHTTPClient()},
	}
}

type gcsCache struct {
	bucket     string
	httpClient *http.Client
	tokens     *gcpTokenSource
}

func (c *gcsCache) Get(ctx context.Context, key string) ([]byte, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcscache: token: %w", err)
	}
	reqURL := fmt.Sprintf("%s/b/%s/o/%s?alt=media", gcsAPIBase, c.bucket, url.PathEscape(key))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcscache: get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, autocert.ErrCacheMiss
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("gcscache: get status %d body=%s", resp.StatusCode, body)
	}
	return io.ReadAll(resp.Body)
}

func (c *gcsCache) Put(ctx context.Context, key string, data []byte) error {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("gcscache: token: %w", err)
	}
	reqURL := fmt.Sprintf("%s/b/%s/o?uploadType=media&name=%s", gcsUploadBase, c.bucket, url.QueryEscape(key))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("gcscache: put: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("gcscache: put status %d body=%s", resp.StatusCode, body)
	}
	return nil
}

func (c *gcsCache) Delete(ctx context.Context, key string) error {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("gcscache: token: %w", err)
	}
	reqURL := fmt.Sprintf("%s/b/%s/o/%s", gcsAPIBase, c.bucket, url.PathEscape(key))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("gcscache: delete: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusNotFound:
		return nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("gcscache: delete status %d body=%s", resp.StatusCode, body)
	}
}

// gcpTokenSource mints access tokens for storage.googleapis.com via
// one of two paths:
//
//  1. GCE-native: GET metadata.google.internal — works on the
//     GCP-side enclaves (Confidential Space VMs have a metadata
//     service the workload SA can read).
//
//  2. Cross-cloud SA key (AWS-side enclave): read
//     GOOGLE_APPLICATION_CREDENTIALS (a path written by the
//     bootstrap RPC to a tmpfs file), parse the SA JSON, sign a
//     short-lived RS256 JWT, exchange it at oauth2.googleapis.com
//     for an access token. This is the same flow Google's own
//     client libraries use internally; we re-implement it here
//     rather than dragging in google.golang.org/api (huge dep,
//     pulls gRPC) just for one token.
//
// On AWS the metadata.google.internal name doesn't resolve, so the
// GCE-native path errors out and we fall through to the SA-key
// path. On GCP the SA-key env is unset so we use metadata directly.
//
// Tokens are cached until 5 minutes before expiry.
type gcpTokenSource struct {
	httpClient *http.Client
	mu         sync.Mutex
	token      string
	expiresAt  time.Time
}

func (s *gcpTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Now().Before(s.expiresAt.Add(-5*time.Minute)) {
		return s.token, nil
	}

	// Cross-cloud SA-key path first if the env is set — this is the
	// definitive signal we're on AWS where metadata.google.internal
	// won't resolve. On GCP this env is unset and we fall through.
	if credPath := strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")); credPath != "" {
		tok, exp, err := s.tokenFromSAKey(ctx, credPath)
		if err == nil {
			s.token, s.expiresAt = tok, exp
			return s.token, nil
		}
		// Fall through to metadata only if the SA-key path errored
		// — surface the failure clearly so misconfigured cross-cloud
		// deploys don't silently spin in retry.
		return "", fmt.Errorf("gcscache: SA-key token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataToken, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata token fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("metadata token status %d body=%s", resp.StatusCode, body)
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return "", fmt.Errorf("metadata token decode: %w", err)
	}
	if t.AccessToken == "" {
		return "", errors.New("metadata token: empty access_token")
	}
	s.token = t.AccessToken
	s.expiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	return s.token, nil
}

// tokenFromSAKey signs a JWT with the service-account RSA key and
// exchanges it at oauth2.googleapis.com for an access token scoped
// to GCS read/write. Returns (token, expiry).
//
// Wire format follows the "JWT Bearer Token Grant" flow described
// in https://developers.google.com/identity/protocols/oauth2/service-account#httprest
// (the same flow Google's client libraries use; reimplemented here
// to avoid pulling in google.golang.org/api).
func (s *gcpTokenSource) tokenFromSAKey(ctx context.Context, credPath string) (string, time.Time, error) {
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

	// Decode PEM-encoded RSA private key.
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
		tokenURI = gcpTokenURL
	}

	now := time.Now()
	// Standard Google service-account JWT: iss=sa-email, scope=GCS,
	// aud=token endpoint, exp=now+1h, iat=now. Sign RS256.
	hdr := `{"alg":"RS256","typ":"JWT"}`
	claim := fmt.Sprintf(
		`{"iss":%q,"scope":%q,"aud":%q,"exp":%d,"iat":%d}`,
		sa.ClientEmail, gcsScope, tokenURI, now.Add(time.Hour).Unix(), now.Unix(),
	)
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(hdr)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(claim))

	// crypto/rsa sign-with-SHA256: hash signingInput then PKCS1v15-sign.
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("rsa sign: %w", err)
	}
	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	// Exchange JWT for access token.
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient.Do(req)
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
	return t.AccessToken, now.Add(time.Duration(t.ExpiresIn) * time.Second), nil
}
