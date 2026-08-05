package batch

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	encryptedArtifactVersion       = 2
	legacyEncryptedArtifactVersion = 1
	defaultBatchDEKCacheTTL        = time.Hour
	defaultBatchDEKCacheEntries    = 256
)

type KMS interface {
	WrapDEK(context.Context, string, []byte, []byte) ([]byte, error)
	UnwrapDEK(context.Context, string, []byte, []byte) ([]byte, error)
}

type Protector interface {
	Seal(context.Context, string, string, []byte) ([]byte, error)
	Open(context.Context, string, string, []byte) ([]byte, error)
}

// EnvelopeProtector uses one KMS-wrapped data key per active batch/key epoch,
// then a unique AES-GCM nonce and artifact-specific AAD for every object. The
// bounded memory-only cache prevents a 50,000-item batch from making tens of
// thousands of KMS calls. Every artifact still carries its wrapped key, so a
// restarted enclave can recover without durable plaintext key material.
type EnvelopeProtector struct {
	KMS          KMS
	KeyName      string
	Rand         io.Reader
	CacheTTL     time.Duration
	CacheEntries int
	Now          func() time.Time

	cacheMu sync.Mutex
	randMu  sync.Mutex
	cache   map[string]*batchDEKCacheEntry
	active  map[string]string
	flights map[string]*batchDEKFlight
	clock   uint64
}

type batchDEKCacheEntry struct {
	batchID   string
	dek       []byte
	wrapped   []byte
	expiresAt time.Time
	lastUsed  uint64
}

type batchDEKFlight struct {
	done chan struct{}
	err  error
}

type encryptedArtifact struct {
	Version    int    `json:"version"`
	KMSKey     string `json:"kms_key"`
	WrappedDEK string `json:"wrapped_dek"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func (p *EnvelopeProtector) Seal(ctx context.Context, batchID, kind string, plaintext []byte) ([]byte, error) {
	if p == nil || p.KMS == nil || p.KeyName == "" {
		return nil, fmt.Errorf("batch encryption unavailable")
	}
	dek, wrapped, err := p.sealKey(ctx, batchID)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if err := p.readRandom(nonce); err != nil {
		return nil, fmt.Errorf("batch encryption nonce: %w", err)
	}
	aad := artifactAAD(encryptedArtifactVersion, batchID, kind)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return json.Marshal(encryptedArtifact{
		Version:    encryptedArtifactVersion,
		KMSKey:     p.KeyName,
		WrappedDEK: base64.StdEncoding.EncodeToString(wrapped),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
}

func (p *EnvelopeProtector) Open(ctx context.Context, batchID, kind string, encoded []byte) ([]byte, error) {
	if p == nil || p.KMS == nil {
		return nil, fmt.Errorf("batch decryption unavailable")
	}
	var artifact encryptedArtifact
	if err := json.Unmarshal(encoded, &artifact); err != nil {
		return nil, fmt.Errorf("batch encrypted artifact: %w", err)
	}
	if artifact.KMSKey == "" || artifact.KMSKey != p.KeyName ||
		(artifact.Version != encryptedArtifactVersion && artifact.Version != legacyEncryptedArtifactVersion) {
		return nil, fmt.Errorf("batch encrypted artifact: unsupported version")
	}
	wrapped, err := base64.StdEncoding.DecodeString(artifact.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("batch wrapped key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(artifact.Nonce)
	if err != nil {
		return nil, fmt.Errorf("batch nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(artifact.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("batch ciphertext: %w", err)
	}
	var dek []byte
	if artifact.Version == legacyEncryptedArtifactVersion {
		dek, err = p.KMS.UnwrapDEK(
			ctx, artifact.KMSKey, wrapped,
			artifactAAD(legacyEncryptedArtifactVersion, batchID, kind),
		)
	} else {
		dek, err = p.openKey(ctx, batchID, wrapped)
	}
	if err != nil {
		return nil, fmt.Errorf("batch unwrap key: %w", err)
	}
	defer clear(dek)
	if len(dek) != 32 {
		return nil, fmt.Errorf("batch unwrapped key: invalid length")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("batch nonce: invalid length")
	}
	plaintext, err := aead.Open(
		nil, nonce, ciphertext,
		artifactAAD(artifact.Version, batchID, kind),
	)
	if err != nil {
		return nil, fmt.Errorf("batch ciphertext authentication failed")
	}
	return plaintext, nil
}

func (p *EnvelopeProtector) sealKey(ctx context.Context, batchID string) ([]byte, []byte, error) {
	p.cacheMu.Lock()
	now := p.now()
	p.pruneExpiredLocked(now)
	if keyID := p.active[batchID]; keyID != "" {
		if entry := p.cache[keyID]; entry != nil {
			p.touchLocked(entry)
			dek, wrapped := cloneBytes(entry.dek), cloneBytes(entry.wrapped)
			p.cacheMu.Unlock()
			return dek, wrapped, nil
		}
	}
	flightKey := "seal\x00" + batchID
	if flight := p.flights[flightKey]; flight != nil {
		p.cacheMu.Unlock()
		if err := waitBatchDEKFlight(ctx, flight); err != nil {
			return nil, nil, err
		}
		return p.sealKey(ctx, batchID)
	}
	flight := &batchDEKFlight{done: make(chan struct{})}
	p.flights[flightKey] = flight
	p.cacheMu.Unlock()

	dek := make([]byte, 32)
	if err := p.readRandom(dek); err != nil {
		err = fmt.Errorf("batch encryption key: %w", err)
		p.completeDEKFlight(flightKey, flight, err)
		return nil, nil, err
	}
	wrapped, err := p.KMS.WrapDEK(ctx, p.KeyName, dek, batchKeyAAD(batchID))
	if err != nil {
		clear(dek)
		err = fmt.Errorf("batch wrap key: %w", err)
		p.completeDEKFlight(flightKey, flight, err)
		return nil, nil, err
	}
	p.cacheMu.Lock()
	now = p.now()
	p.pruneExpiredLocked(now)
	entry := &batchDEKCacheEntry{
		batchID:   batchID,
		dek:       cloneBytes(dek),
		wrapped:   cloneBytes(wrapped),
		expiresAt: now.Add(p.cacheTTL()),
	}
	keyID := batchDEKCacheKey(batchID, wrapped)
	p.touchLocked(entry)
	p.ensureCacheLocked()
	p.cache[keyID] = entry
	p.active[batchID] = keyID
	p.evictLocked(keyID)
	delete(p.flights, flightKey)
	close(flight.done)
	p.cacheMu.Unlock()
	return dek, cloneBytes(wrapped), nil
}

func (p *EnvelopeProtector) openKey(ctx context.Context, batchID string, wrapped []byte) ([]byte, error) {
	p.cacheMu.Lock()
	now := p.now()
	p.pruneExpiredLocked(now)
	keyID := batchDEKCacheKey(batchID, wrapped)
	if entry := p.cache[keyID]; entry != nil {
		p.touchLocked(entry)
		dek := cloneBytes(entry.dek)
		p.cacheMu.Unlock()
		return dek, nil
	}
	flightKey := "open\x00" + keyID
	if flight := p.flights[flightKey]; flight != nil {
		p.cacheMu.Unlock()
		if err := waitBatchDEKFlight(ctx, flight); err != nil {
			return nil, err
		}
		return p.openKey(ctx, batchID, wrapped)
	}
	flight := &batchDEKFlight{done: make(chan struct{})}
	p.flights[flightKey] = flight
	p.cacheMu.Unlock()

	dek, err := p.KMS.UnwrapDEK(ctx, p.KeyName, wrapped, batchKeyAAD(batchID))
	if err != nil {
		p.completeDEKFlight(flightKey, flight, err)
		return nil, err
	}
	if len(dek) != 32 {
		clear(dek)
		err = fmt.Errorf("invalid key length")
		p.completeDEKFlight(flightKey, flight, err)
		return nil, err
	}
	p.cacheMu.Lock()
	now = p.now()
	p.pruneExpiredLocked(now)
	entry := &batchDEKCacheEntry{
		batchID:   batchID,
		dek:       cloneBytes(dek),
		wrapped:   cloneBytes(wrapped),
		expiresAt: now.Add(p.cacheTTL()),
	}
	p.touchLocked(entry)
	p.ensureCacheLocked()
	p.cache[keyID] = entry
	if p.active[batchID] == "" {
		p.active[batchID] = keyID
	}
	p.evictLocked(keyID)
	delete(p.flights, flightKey)
	close(flight.done)
	p.cacheMu.Unlock()
	return dek, nil
}

func (p *EnvelopeProtector) completeDEKFlight(
	flightKey string,
	flight *batchDEKFlight,
	err error,
) {
	p.cacheMu.Lock()
	flight.err = err
	delete(p.flights, flightKey)
	close(flight.done)
	p.cacheMu.Unlock()
}

func waitBatchDEKFlight(
	ctx context.Context,
	flight *batchDEKFlight,
) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-flight.done:
	}
	return flight.err
}

func (p *EnvelopeProtector) ensureCacheLocked() {
	if p.cache == nil {
		p.cache = make(map[string]*batchDEKCacheEntry)
	}
	if p.active == nil {
		p.active = make(map[string]string)
	}
	if p.flights == nil {
		p.flights = make(map[string]*batchDEKFlight)
	}
}

func (p *EnvelopeProtector) pruneExpiredLocked(now time.Time) {
	p.ensureCacheLocked()
	for keyID, entry := range p.cache {
		if now.Before(entry.expiresAt) {
			continue
		}
		clear(entry.dek)
		delete(p.cache, keyID)
		if p.active[entry.batchID] == keyID {
			delete(p.active, entry.batchID)
		}
	}
}

func (p *EnvelopeProtector) evictLocked(protectedKeyID string) {
	for len(p.cache) > p.cacheEntries() {
		oldestKey := ""
		var oldest uint64
		for keyID, entry := range p.cache {
			if keyID == protectedKeyID || (oldestKey != "" && entry.lastUsed >= oldest) {
				continue
			}
			oldestKey = keyID
			oldest = entry.lastUsed
		}
		if oldestKey == "" {
			return
		}
		entry := p.cache[oldestKey]
		clear(entry.dek)
		delete(p.cache, oldestKey)
		if p.active[entry.batchID] == oldestKey {
			delete(p.active, entry.batchID)
		}
	}
}

func (p *EnvelopeProtector) touchLocked(entry *batchDEKCacheEntry) {
	p.clock++
	entry.lastUsed = p.clock
}

func (p *EnvelopeProtector) readRandom(destination []byte) error {
	p.randMu.Lock()
	defer p.randMu.Unlock()
	random := p.Rand
	if random == nil {
		random = rand.Reader
	}
	_, err := io.ReadFull(random, destination)
	return err
}

func (p *EnvelopeProtector) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *EnvelopeProtector) cacheTTL() time.Duration {
	if p.CacheTTL > 0 {
		return p.CacheTTL
	}
	return defaultBatchDEKCacheTTL
}

func (p *EnvelopeProtector) cacheEntries() int {
	if p.CacheEntries > 0 {
		return p.CacheEntries
	}
	return defaultBatchDEKCacheEntries
}

func batchDEKCacheKey(batchID string, wrapped []byte) string {
	digest := sha256.Sum256(wrapped)
	return batchID + "\x00" + hex.EncodeToString(digest[:])
}

func batchKeyAAD(batchID string) []byte {
	return []byte("trustedrouter:batch-key:v2:" + batchID)
}

func artifactAAD(version int, batchID, kind string) []byte {
	return []byte(fmt.Sprintf("trustedrouter:batch:v%d:%s:%s", version, batchID, kind))
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}
