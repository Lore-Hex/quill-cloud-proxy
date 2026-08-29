// Package byokcache decrypts TrustedRouter secret envelopes inside the
// attested gateway and keeps plaintext provider or owner endpoint keys only in
// short-lived process memory.
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
	// AlgorithmV2 length-prefixes the associated data and adds a namespace.
	// V1 read support was removed only after every standalone cloud attested
	// that no V1 envelope remained.
	AlgorithmV2 = "TR-BYOK-ENVELOPE-AES-256-GCM-V2"

	// The enclave opens provider BYOK keys and owner-supplied model endpoint
	// credentials. Control secrets remain control-plane-only. Keeping the
	// user-model family in its own AAD namespace prevents a provider key or a
	// control purpose with the same spelling from being substituted here.
	namespaceProvider  = "provider"
	namespaceUserModel = "user_model"
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
	namespace   string
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
	if strings.ContainsRune(workspaceID, '\x00') || strings.ContainsRune(provider, '\x00') {
		return "", false, errors.New("byokcache: provider cache identity contains a NUL byte")
	}
	derivedKey := Fingerprint(workspaceID, provider, envelope)
	if cacheKey != "" && cacheKey != derivedKey {
		return "", false, errors.New("byokcache: supplied cache key does not match envelope binding")
	}
	return c.resolve(ctx, namespaceProvider, workspaceID, provider, derivedKey, envelope)
}

// ResolveUserModel opens an owner endpoint credential under the user_model
// namespace. This family was introduced after AAD v2, so accepting a v1
// envelope would erase the namespace separation at the trust boundary.
//
// The cache key is always derived inside the enclave. The control plane is
// intentionally not allowed to choose a key that could alias another owner's
// plaintext secret.
func (c *Cache) ResolveUserModel(
	ctx context.Context,
	ownerWorkspaceID string,
	purpose string,
	envelope EncryptedSecretEnvelope,
) (string, bool, error) {
	cacheKey, err := userModelFingerprint(ownerWorkspaceID, purpose, envelope)
	if err != nil {
		return "", false, err
	}
	return c.resolve(
		ctx,
		namespaceUserModel,
		ownerWorkspaceID,
		purpose,
		cacheKey,
		envelope,
	)
}

func (c *Cache) resolve(
	ctx context.Context,
	namespace string,
	workspaceID string,
	contextName string,
	cacheKey string,
	envelope EncryptedSecretEnvelope,
) (string, bool, error) {
	if c == nil {
		return "", false, errors.New("byokcache: nil cache")
	}
	// Validate the wire format before lookup. Cache identity is a performance
	// detail and must never let a relabeled or retired envelope bypass the
	// format gate on a hit.
	if envelope.Algorithm != AlgorithmV2 {
		return "", false, fmt.Errorf(
			"byokcache: unsupported envelope algorithm %q", envelope.Algorithm,
		)
	}
	if cacheKey == "" {
		return "", false, errors.New("byokcache: empty enclave-derived cache key")
	}
	// Namespace the enclave-derived lookup key. A provider entry cannot bypass
	// user_model AAD verification by colliding with that family's fingerprint.
	cacheKey = namespace + "\x00" + cacheKey

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

	secret, err := decryptEnvelope(ctx, c.unwrapper, namespace, workspaceID, contextName, envelope)
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
		namespace:   namespace,
		workspaceID: workspaceID,
		provider:    contextName,
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
		if cached.namespace == namespaceProvider && cached.workspaceID == workspaceID && cached.provider == provider {
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
	namespace string,
	workspaceID string,
	contextName string,
	envelope EncryptedSecretEnvelope,
) (string, error) {
	if unwrapper == nil {
		return "", errors.New("byokcache: DEK unwrapper is required")
	}

	aad, err := envelopeAAD(envelope.Algorithm, namespace, workspaceID, contextName)
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
		return "", fmt.Errorf("byokcache: decrypt envelope: %w", err)
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
	// "v1" versions the cache-key serialization, not the encrypted-envelope
	// format. It remains stable so a rolling enclave update does not create a
	// second cache identity for the same V2 envelope.
	return "byokcache:v1:" + hex.EncodeToString(digest.Sum(nil))
}

func userModelFingerprint(ownerWorkspaceID, purpose string, envelope EncryptedSecretEnvelope) (string, error) {
	identity, err := aadV2(namespaceUserModel, ownerWorkspaceID, purpose)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	parts := [][]byte{
		identity,
		[]byte(envelope.Algorithm),
		[]byte(envelope.KeyRef),
		[]byte(envelope.EncryptedDEK),
		[]byte(envelope.DEKNonce),
		[]byte(envelope.Ciphertext),
		[]byte(envelope.Nonce),
	}
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write(part)
	}
	return "byokcache:user-model:v1:" + hex.EncodeToString(digest.Sum(nil)), nil
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

// envelopeAAD accepts only the current format. The control family remains
// control-plane-only and is deliberately rejected.
func envelopeAAD(algorithm, namespace, workspaceID, contextName string) ([]byte, error) {
	if algorithm != AlgorithmV2 {
		return nil, fmt.Errorf("byokcache: unsupported envelope algorithm %q", algorithm)
	}
	switch namespace {
	case namespaceProvider, namespaceUserModel:
		return aadV2(namespace, workspaceID, contextName)
	default:
		return nil, fmt.Errorf("byokcache: unsupported envelope namespace %q", namespace)
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
