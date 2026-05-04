// Package byokcache decrypts TrustedRouter BYOK envelopes inside the
// attested gateway and keeps plaintext provider keys only in short-lived
// process memory.
package byokcache

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const Algorithm = "TR-BYOK-ENVELOPE-AES-256-GCM-V1"

const defaultTTL = 2 * time.Minute

// EncryptedSecretEnvelope mirrors trusted_router.storage_models.
// It contains no plaintext provider key or plaintext DEK.
type EncryptedSecretEnvelope struct {
	Algorithm    string `json:"algorithm"`
	KeyRef       string `json:"key_ref"`
	EncryptedDEK string `json:"encrypted_dek"`
	DEKNonce     string `json:"dek_nonce"`
	Ciphertext   string `json:"ciphertext"`
	Nonce        string `json:"nonce"`
}

// DEKUnwrapper unwraps the per-secret data-encryption key. Production uses
// Google Cloud KMS; tests inject a deterministic fake.
type DEKUnwrapper interface {
	UnwrapDEK(ctx context.Context, keyName string, encryptedDEK, aad []byte) ([]byte, error)
}

type Options struct {
	TTL       time.Duration
	Unwrapper DEKUnwrapper
	Now       func() time.Time
}

type Cache struct {
	mu        sync.Mutex
	ttl       time.Duration
	unwrapper DEKUnwrapper
	now       func() time.Time
	entries   map[string]entry
}

type entry struct {
	workspaceID string
	provider    string
	secret      string
	expiresAt   time.Time
}

func New(opts Options) *Cache {
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Cache{
		ttl:       ttl,
		unwrapper: opts.Unwrapper,
		now:       now,
		entries:   make(map[string]entry),
	}
}

// Resolve returns the raw BYOK provider key. The boolean is true when the
// value came from the in-memory cache.
func (c *Cache) Resolve(
	ctx context.Context,
	workspaceID string,
	provider string,
	cacheKey string,
	envelope EncryptedSecretEnvelope,
) (string, bool, error) {
	if c == nil {
		return "", false, errors.New("byokcache: nil cache")
	}
	if cacheKey == "" {
		cacheKey = Fingerprint(workspaceID, provider, envelope)
	}

	now := c.now()
	c.mu.Lock()
	c.pruneLocked(now)
	if cached, ok := c.entries[cacheKey]; ok && now.Before(cached.expiresAt) {
		secret := cached.secret
		c.mu.Unlock()
		return secret, true, nil
	}
	c.mu.Unlock()

	secret, err := decryptEnvelope(ctx, c.unwrapper, workspaceID, provider, envelope)
	if err != nil {
		return "", false, err
	}

	c.mu.Lock()
	c.entries[cacheKey] = entry{
		workspaceID: workspaceID,
		provider:    provider,
		secret:      secret,
		expiresAt:   now.Add(c.ttl),
	}
	c.mu.Unlock()
	return secret, false, nil
}

func (c *Cache) InvalidateProvider(workspaceID, provider string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, cached := range c.entries {
		if cached.workspaceID == workspaceID && cached.provider == provider {
			delete(c.entries, key)
		}
	}
}

func (c *Cache) InvalidateWorkspace(workspaceID string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, cached := range c.entries {
		if cached.workspaceID == workspaceID {
			delete(c.entries, key)
		}
	}
}

func (c *Cache) Size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(c.now())
	return len(c.entries)
}

func (c *Cache) pruneLocked(now time.Time) {
	for key, cached := range c.entries {
		if !now.Before(cached.expiresAt) {
			delete(c.entries, key)
		}
	}
}

func decryptEnvelope(
	ctx context.Context,
	unwrapper DEKUnwrapper,
	workspaceID string,
	provider string,
	envelope EncryptedSecretEnvelope,
) (string, error) {
	if envelope.Algorithm != Algorithm {
		return "", fmt.Errorf("byokcache: unsupported envelope algorithm %q", envelope.Algorithm)
	}
	if unwrapper == nil {
		return "", errors.New("byokcache: DEK unwrapper is required")
	}

	aad := aad(workspaceID, provider)
	encryptedDEK, err := decodeB64(envelope.EncryptedDEK)
	if err != nil {
		return "", fmt.Errorf("byokcache: decode encrypted DEK: %w", err)
	}
	dek, err := unwrapper.UnwrapDEK(ctx, envelope.KeyRef, encryptedDEK, aad)
	if err != nil {
		return "", fmt.Errorf("byokcache: unwrap DEK: %w", err)
	}
	if len(dek) != 32 {
		return "", fmt.Errorf("byokcache: unwrapped DEK has %d bytes, want 32", len(dek))
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("byokcache: DEK cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("byokcache: DEK GCM: %w", err)
	}
	nonce, err := decodeB64(envelope.Nonce)
	if err != nil {
		return "", fmt.Errorf("byokcache: decode nonce: %w", err)
	}
	ciphertext, err := decodeB64(envelope.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("byokcache: decode ciphertext: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", fmt.Errorf("byokcache: decrypt provider key: %w", err)
	}
	return string(plaintext), nil
}

func Fingerprint(workspaceID string, provider string, envelope EncryptedSecretEnvelope) string {
	digest := sha256.New()
	for _, part := range []string{
		workspaceID,
		provider,
		envelope.Algorithm,
		envelope.KeyRef,
		envelope.EncryptedDEK,
		envelope.DEKNonce,
		envelope.Ciphertext,
		envelope.Nonce,
	} {
		_, _ = digest.Write([]byte(part))
		_, _ = digest.Write([]byte{0})
	}
	return "byokcache:v1:" + hex.EncodeToString(digest.Sum(nil))
}

func aad(workspaceID, provider string) []byte {
	return []byte(fmt.Sprintf("trustedrouter:byok:%s:%s", workspaceID, provider))
}

func decodeB64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.URLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
