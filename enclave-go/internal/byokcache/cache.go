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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	// Algorithm is the original envelope format. Its associated data is
	// colon-joined and not injective; see aad below.
	Algorithm = "TR-BYOK-ENVELOPE-AES-256-GCM-V1"

	// AlgorithmV2 length-prefixes the associated data and adds a namespace
	// component. The control plane starts writing these only after every
	// enclave region can read them — a v2 envelope reaching a build that only
	// knows v1 is a hard failure for that customer's BYOK key.
	AlgorithmV2 = "TR-BYOK-ENVELOPE-AES-256-GCM-V2"

	// namespaceProvider is the only namespace the enclave sees. Control
	// secrets are decrypted in the control plane and never reach here.
	namespaceProvider = "provider"
)

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
	if unwrapper == nil {
		return "", errors.New("byokcache: DEK unwrapper is required")
	}

	aad, err := envelopeAAD(envelope.Algorithm, workspaceID, provider)
	if err != nil {
		return "", err
	}
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

// aad builds the v1 associated data.
//
// Colon-joined with no escaping and no length prefix, so component boundaries
// are ambiguous: ("a:b","c") and ("a","b:c") produce identical bytes. That is
// the defect v2 exists to fix. Kept because envelopes written before the
// migration are still v1 and must keep opening.
func aad(workspaceID, provider string) []byte {
	return []byte(fmt.Sprintf("trustedrouter:byok:%s:%s", workspaceID, provider))
}

// aadV2 builds the v2 associated data: length-prefixed, so no choice of
// component values can produce the same bytes from a different tuple.
//
// Each component is a 4-byte big-endian length followed by its UTF-8 bytes.
// The namespace component separates secret families, so a control-secret
// purpose can never collide with a provider slug even if the strings match.
//
// Must stay byte-identical to _aad_v2 in quill-router's byok_crypto.py. A
// divergence here is not a test failure, it is every BYOK key in that family
// failing to decrypt.
func aadV2(namespace, workspaceID, context string) ([]byte, error) {
	parts := [][]byte{
		[]byte("trustedrouter/byok/v2"),
		[]byte(namespace),
		[]byte(workspaceID),
		[]byte(context),
	}
	out := make([]byte, 0, 64)
	var length [4]byte
	for _, part := range parts {
		// A component longer than a uint32 cannot be length-prefixed in this
		// encoding. These are identifiers — a namespace, a workspace UUID, a
		// provider slug — so this is unreachable in practice, but an unchecked
		// int->uint32 narrowing in the function that derives AEAD associated
		// data is not something to leave to reasoning about callers: a wrapped
		// length would silently produce a DIFFERENT tuple's AAD.
		if uint64(len(part)) > math.MaxUint32 {
			return nil, fmt.Errorf("byokcache: AAD component is %d bytes, over the uint32 limit", len(part))
		}
		// The bound above makes this conversion total; gosec cannot see that.
		binary.BigEndian.PutUint32(length[:], uint32(len(part))) //nolint:gosec // bounded above
		out = append(out, length[:]...)
		out = append(out, part...)
	}
	return out, nil
}

// envelopeAAD selects the associated data for an envelope's declared format.
//
// The enclave only ever decrypts BYOK provider secrets — settlement.go reaches
// byokcache exclusively for candidates whose UsageType is BYOK — so the
// namespace is always "provider" here. Control secrets are decrypted in the
// control plane and never cross this boundary.
func envelopeAAD(algorithm, workspaceID, provider string) ([]byte, error) {
	switch algorithm {
	case Algorithm:
		return aad(workspaceID, provider), nil
	case AlgorithmV2:
		return aadV2(namespaceProvider, workspaceID, provider)
	default:
		return nil, fmt.Errorf("byokcache: unsupported envelope algorithm %q", algorithm)
	}
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
