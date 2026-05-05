package byokcache

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

type fakeUnwrapper struct {
	dek   []byte
	calls int
}

func (f *fakeUnwrapper) UnwrapDEK(_ context.Context, _ string, _ []byte, _ []byte) ([]byte, error) {
	f.calls++
	return append([]byte(nil), f.dek...), nil
}

func TestResolveUsesKMSOnceWithinTTL(t *testing.T) {
	now := time.Unix(100, 0)
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{
		TTL:       time.Minute,
		Unwrapper: unwrapper,
		Now:       func() time.Time { return now },
	})
	wantSecret := strings.Join([]string{"csk", "live", "user", "owned", "key"}, "-")
	envelope := testEnvelope(t, "workspace-1", "cerebras", wantSecret)
	cacheKey := Fingerprint("workspace-1", "cerebras", envelope)

	secret, cached, err := cache.Resolve(t.Context(), "workspace-1", "cerebras", cacheKey, envelope)
	if err != nil {
		t.Fatalf("Resolve first: %v", err)
	}
	if cached {
		t.Fatal("first resolve unexpectedly came from cache")
	}
	if secret != wantSecret {
		t.Fatalf("secret = %q", secret)
	}

	secret, cached, err = cache.Resolve(t.Context(), "workspace-1", "cerebras", cacheKey, envelope)
	if err != nil {
		t.Fatalf("Resolve second: %v", err)
	}
	if !cached {
		t.Fatal("second resolve did not use cache")
	}
	if secret != wantSecret {
		t.Fatalf("secret = %q", secret)
	}
	if unwrapper.calls != 1 {
		t.Fatalf("unwrapper calls = %d, want 1", unwrapper.calls)
	}
}

func TestResolveExpiresAfterTTL(t *testing.T) {
	now := time.Unix(100, 0)
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{
		TTL:       time.Minute,
		Unwrapper: unwrapper,
		Now:       func() time.Time { return now },
	})
	envelope := testEnvelope(t, "workspace-1", "cerebras", "secret")
	cacheKey := Fingerprint("workspace-1", "cerebras", envelope)

	if _, _, err := cache.Resolve(t.Context(), "workspace-1", "cerebras", cacheKey, envelope); err != nil {
		t.Fatalf("Resolve first: %v", err)
	}
	now = now.Add(time.Minute + time.Second)
	_, cached, err := cache.Resolve(t.Context(), "workspace-1", "cerebras", cacheKey, envelope)
	if err != nil {
		t.Fatalf("Resolve after TTL: %v", err)
	}
	if cached {
		t.Fatal("resolve after TTL unexpectedly used cache")
	}
	if unwrapper.calls != 2 {
		t.Fatalf("unwrapper calls = %d, want 2", unwrapper.calls)
	}
}

func TestRotationCacheKeyForcesDecryptAndNewSecret(t *testing.T) {
	now := time.Unix(100, 0)
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{
		TTL:       10 * time.Minute,
		Unwrapper: unwrapper,
		Now:       func() time.Time { return now },
	})
	first := testEnvelope(t, "workspace-1", "kimi", "first-key")
	rotated := testEnvelope(t, "workspace-1", "kimi", "rotated-key")
	firstKey := Fingerprint("workspace-1", "kimi", first)
	rotatedKey := Fingerprint("workspace-1", "kimi", rotated)
	if firstKey == rotatedKey {
		t.Fatal("rotation did not change cache key")
	}

	firstSecret, _, err := cache.Resolve(t.Context(), "workspace-1", "kimi", firstKey, first)
	if err != nil {
		t.Fatalf("Resolve first: %v", err)
	}
	rotatedSecret, cached, err := cache.Resolve(t.Context(), "workspace-1", "kimi", rotatedKey, rotated)
	if err != nil {
		t.Fatalf("Resolve rotated: %v", err)
	}
	if cached {
		t.Fatal("rotated envelope unexpectedly reused cached plaintext")
	}
	if firstSecret != "first-key" || rotatedSecret != "rotated-key" {
		t.Fatalf("secrets = %q %q", firstSecret, rotatedSecret)
	}
	if unwrapper.calls != 2 {
		t.Fatalf("unwrapper calls = %d, want 2", unwrapper.calls)
	}
}

func TestFingerprintMatchesControlPlaneAlgorithm(t *testing.T) {
	envelope := EncryptedSecretEnvelope{
		Algorithm:    Algorithm,
		KeyRef:       "projects/test/locations/us/keyRings/tr/cryptoKeys/byok",
		EncryptedDEK: "wrapped-dek",
		DEKNonce:     "dek-nonce-123",
		Ciphertext:   "ciphertext",
		Nonce:        "nonce",
	}
	got := Fingerprint("workspace-1", "cerebras", envelope)
	want := "byokcache:v1:8503c4b9574a775e56ee2ccfffcad2d958b995073685ee6b8b70c57ea983a1b0"
	if got != want {
		t.Fatalf("Fingerprint = %q, want %q", got, want)
	}
}

func TestInvalidateProviderDropsCachedSecret(t *testing.T) {
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{TTL: 10 * time.Minute, Unwrapper: unwrapper})
	envelope := testEnvelope(t, "workspace-1", "mistral", "secret")
	cacheKey := Fingerprint("workspace-1", "mistral", envelope)

	if _, _, err := cache.Resolve(t.Context(), "workspace-1", "mistral", cacheKey, envelope); err != nil {
		t.Fatalf("Resolve first: %v", err)
	}
	cache.InvalidateProvider("workspace-1", "mistral")
	_, cached, err := cache.Resolve(t.Context(), "workspace-1", "mistral", cacheKey, envelope)
	if err != nil {
		t.Fatalf("Resolve second: %v", err)
	}
	if cached {
		t.Fatal("resolve after invalidation unexpectedly used cache")
	}
	if unwrapper.calls != 2 {
		t.Fatalf("unwrapper calls = %d, want 2", unwrapper.calls)
	}
}

func TestDecryptRejectsWrongWorkspaceAAD(t *testing.T) {
	cache := New(Options{Unwrapper: &fakeUnwrapper{dek: fixedDEK()}})
	envelope := testEnvelope(t, "workspace-1", "deepseek", "secret")
	_, _, err := cache.Resolve(t.Context(), "workspace-2", "deepseek", "", envelope)
	if err == nil {
		t.Fatal("expected decrypt failure")
	}
	if !strings.Contains(err.Error(), "message authentication failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func fixedDEK() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func testEnvelope(t *testing.T, workspaceID, provider, secret string) EncryptedSecretEnvelope {
	t.Helper()
	dek := fixedDEK()
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("123456789012")
	aad := aad(workspaceID, provider)
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), aad)
	return EncryptedSecretEnvelope{
		Algorithm:    Algorithm,
		KeyRef:       "projects/test/locations/us/keyRings/tr/cryptoKeys/byok",
		EncryptedDEK: base64.URLEncoding.EncodeToString([]byte("wrapped-dek")),
		DEKNonce:     base64.URLEncoding.EncodeToString([]byte("dek-nonce-123")),
		Ciphertext:   base64.URLEncoding.EncodeToString(ciphertext),
		Nonce:        base64.URLEncoding.EncodeToString(nonce),
	}
}
