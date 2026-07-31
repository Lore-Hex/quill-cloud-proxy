// Package byokcache decrypts TrustedRouter BYOK envelopes inside the
// attested gateway and keeps plaintext provider keys only in short-lived
// process memory.
package byokcache

import (
	"container/list"
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

const (
	defaultTTL        = 2 * time.Minute
	defaultMaxEntries = 50_000
)

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
	TTL        time.Duration
	MaxEntries int
	Unwrapper  DEKUnwrapper
	Now        func() time.Time
}

type Cache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	unwrapper  DEKUnwrapper
	now        func() time.Time
	entries    map[string]*list.Element
	order      list.List
}

type entry struct {
	cacheKey    string
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
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Cache{
		ttl:        ttl,
		maxEntries: maxEntries,
		unwrapper:  opts.Unwrapper,
		now:        now,
		entries:    make(map[string]*list.Element),
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
	if element, ok := c.entries[cacheKey]; ok {
		cached := element.Value.(entry)
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
	insertedAt := c.now()
	c.pruneLocked(insertedAt)
	if existing, ok := c.entries[cacheKey]; ok {
		c.removeLocked(existing)
	}
	for len(c.entries) >= c.maxEntries {
		oldest := c.order.Front()
		if oldest == nil {
			break
		}
		c.removeLocked(oldest)
	}
	inserted := c.order.PushBack(entry{
		cacheKey:    cacheKey,
		workspaceID: workspaceID,
		provider:    provider,
		secret:      secret,
		expiresAt:   insertedAt.Add(c.ttl),
	})
	c.entries[cacheKey] = inserted
	c.mu.Unlock()
	return secret, false, nil
}

func (c *Cache) InvalidateProvider(workspaceID, provider string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, element := range c.entries {
		cached := element.Value.(entry)
		if cached.workspaceID == workspaceID && cached.provider == provider {
			c.removeLocked(element)
		}
	}
}

func (c *Cache) InvalidateWorkspace(workspaceID string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, element := range c.entries {
		cached := element.Value.(entry)
		if cached.workspaceID == workspaceID {
			c.removeLocked(element)
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
	for {
		oldest := c.order.Front()
		if oldest == nil {
			return
		}
		cached := oldest.Value.(entry)
		if now.Before(cached.expiresAt) {
			return
		}
		c.removeLocked(oldest)
	}
}

func (c *Cache) removeLocked(element *list.Element) {
	cached := element.Value.(entry)
	delete(c.entries, cached.cacheKey)
	c.order.Remove(element)
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
