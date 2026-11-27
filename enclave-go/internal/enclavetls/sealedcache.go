package enclavetls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// One fresh local AES-256 key per write. Only this short key reaches KMS;
// neither TLS nor ACME signing keys leave the workload in plaintext.
type CacheKeyWrapper interface {
	WrapDEK(context.Context, string, []byte, []byte) ([]byte, error)
	UnwrapDEK(context.Context, string, []byte, []byte) ([]byte, error)
}

const (
	sealedCacheV1      = "TRACME01"
	maxACMEPlaintext   = 1 << 20
	maxWrappedDEK      = 16 << 10
	maxACMEObjectBytes = maxACMEPlaintext + maxWrappedDEK + 64
)

type sealedACMECache struct {
	store          autocert.Cache
	wrapper        CacheKeyWrapper
	bucket, kmsKey string
}

func (c *sealedACMECache) aad(name string) []byte {
	return []byte(strings.Join([]string{sealedCacheV1, c.bucket, c.kmsKey, name}, "\x00"))
}

func cacheCipher(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("ACME cache requires a 256-bit data key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func (c *sealedACMECache) Put(ctx context.Context, name string, data []byte) error {
	if len(data) > maxACMEPlaintext {
		return errors.New("ACME cache value too large")
	}
	dek := make([]byte, 32)
	defer clear(dek)
	if _, err := rand.Read(dek); err != nil {
		return err
	}
	aead, err := cacheCipher(dek)
	if err != nil {
		return err
	}
	aad := c.aad(name)
	wrapped, err := c.wrapper.WrapDEK(ctx, c.kmsKey, dek, aad)
	if err != nil || len(wrapped) == 0 || len(wrapped) > maxWrappedDEK {
		return errors.New("ACME cache data-key wrap failed")
	}
	header := binary.BigEndian.AppendUint32([]byte(sealedCacheV1), uint32(len(wrapped))) // #nosec G115 -- bounded above.
	header = append(header, wrapped...)
	return c.store.Put(ctx, name, aead.Seal(header, nil, data, aad))
}

func (c *sealedACMECache) Get(ctx context.Context, name string) ([]byte, error) {
	blob, err := c.store.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	const headerLen = len(sealedCacheV1) + 4
	if len(blob) <= headerLen || len(blob) > maxACMEObjectBytes || string(blob[:len(sealedCacheV1)]) != sealedCacheV1 {
		return nil, errors.New("invalid sealed ACME cache entry")
	}
	n := binary.BigEndian.Uint32(blob[len(sealedCacheV1):headerLen])
	if n == 0 || n > maxWrappedDEK || int64(headerLen)+int64(n) >= int64(len(blob)) {
		return nil, errors.New("invalid sealed ACME cache key length")
	}
	end := headerLen + int(n)
	aad := c.aad(name)
	dek, err := c.wrapper.UnwrapDEK(ctx, c.kmsKey, blob[headerLen:end], aad)
	defer clear(dek)
	if err != nil {
		return nil, errors.New("ACME cache data-key unwrap failed")
	}
	aead, err := cacheCipher(dek)
	if err != nil {
		return nil, err
	}
	if len(blob[end:]) < aead.Overhead() || len(blob[end:]) > maxACMEPlaintext+aead.Overhead() {
		return nil, errors.New("invalid sealed ACME cache payload length")
	}
	return aead.Open(nil, nil, blob[end:], aad)
}

func (c *sealedACMECache) Delete(ctx context.Context, name string) error {
	return c.store.Delete(ctx, name)
}
