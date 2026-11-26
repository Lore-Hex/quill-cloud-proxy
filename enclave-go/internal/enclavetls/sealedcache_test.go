package enclavetls

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

type fixtureKeyWrap struct {
	cipher cipher.AEAD
	denied bool
}

func (f *fixtureKeyWrap) WrapDEK(_ context.Context, _ string, key, aad []byte) ([]byte, error) {
	if len(key) != 32 || f.denied {
		return nil, errors.New("denied")
	}
	return f.cipher.Seal(nil, nil, key, aad), nil
}

func (f *fixtureKeyWrap) UnwrapDEK(_ context.Context, _ string, blob, aad []byte) ([]byte, error) {
	if f.denied {
		return nil, errors.New("denied")
	}
	return f.cipher.Open(nil, nil, blob, aad)
}

func TestSealedCacheBoundaries(t *testing.T) {
	ctx := context.Background()
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	aead, err := cacheCipher(root)
	if err != nil {
		t.Fatal(err)
	}
	auth := &fixtureKeyWrap{cipher: aead}
	backing := newMemoryACMECache()
	c := &sealedACMECache{backing, auth, "test-bucket", "test-key"}
	name := "fixture.invalid"
	data := []byte("synthetic certificate cache fixture that must not appear in storage")
	if _, err := c.Get(ctx, name); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatal("missing entry not reported")
	}
	if err := c.Put(ctx, name, data); err != nil {
		t.Fatal(err)
	}
	blob, err := backing.Get(ctx, name)
	if err != nil || bytes.Contains(blob, data) || !bytes.HasPrefix(blob, []byte(sealedCacheV1)) {
		t.Fatal("entry not enveloped")
	}
	otherReplica := &sealedACMECache{backing, auth, c.bucket, c.kmsKey}
	if got, err := otherReplica.Get(ctx, name); err != nil || !bytes.Equal(got, data) {
		t.Fatal("replica round trip failed", err)
	}
	if err := c.Put(ctx, name, data); err != nil {
		t.Fatal(err)
	}
	second, err := backing.Get(ctx, name)
	if err != nil || bytes.Equal(blob, second) {
		t.Fatal("write did not use fresh encryption")
	}
	auth.denied = true
	if err := c.Put(ctx, name, []byte("replacement")); err == nil {
		t.Fatal("unauthorized write succeeded")
	}
	if got, err := c.Get(ctx, name); got != nil || err == nil || errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatal("denied read did not fail closed")
	}
	auth.denied = false
	if got, err := backing.Get(ctx, name); err != nil || !bytes.Equal(second, got) {
		t.Fatal("failed wrap replaced the prior object")
	}
	for _, bad := range [][]byte{data, []byte(sealedCacheV1), second[:len(second)-1]} {
		if err := backing.Put(ctx, name, bad); err != nil {
			t.Fatal(err)
		}
		if got, err := c.Get(ctx, name); got != nil || err == nil || errors.Is(err, autocert.ErrCacheMiss) {
			t.Fatal("invalid entry did not fail closed")
		}
	}
	if err := backing.Put(ctx, "second.invalid", second); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Get(ctx, "second.invalid"); got != nil || err == nil {
		t.Fatal("entry was accepted under another name")
	}
	if err := c.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, name); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatal("delete did not remove object")
	}
}
