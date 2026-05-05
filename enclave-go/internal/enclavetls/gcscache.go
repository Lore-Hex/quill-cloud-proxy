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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const (
	gcsAPIBase    = "https://storage.googleapis.com/storage/v1"
	gcsUploadBase = "https://storage.googleapis.com/upload/storage/v1"
	metadataToken = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- metadata endpoint URL, not a secret.
)

// NewGCSCache returns an autocert.Cache backed by GCS. Callers should pass
// the bucket name only (no `gs://` prefix). The workload's GCE SA must
// hold storage.objectAdmin on the bucket, and the bucket should have CMEK
// encryption configured at rest — handled by infra (deploy script /
// terraform), not by this code.
func NewGCSCache(bucket string) autocert.Cache {
	return &gcsCache{
		bucket:     bucket,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		tokens:     &gcpTokenSource{httpClient: &http.Client{Timeout: 5 * time.Second}},
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

// gcpTokenSource fetches access tokens from the GCE metadata server and
// caches them until five minutes before expiry.
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
