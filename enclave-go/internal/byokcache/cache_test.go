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

func TestResolveRejectsControlPlaneCacheKeyMismatchBeforeUnwrap(t *testing.T) {
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{Unwrapper: unwrapper})
	envelope := testEnvelope(t, "workspace-1", "cerebras", "workspace-1-secret")

	if _, _, err := cache.Resolve(
		t.Context(), "workspace-1", "cerebras", "control-plane-chosen-key", envelope,
	); err == nil || !strings.Contains(err.Error(), "does not match envelope binding") {
		t.Fatalf("mismatched cache key error = %v", err)
	}
	if unwrapper.calls != 0 {
		t.Fatalf("mismatched cache key reached the DEK unwrapper %d times", unwrapper.calls)
	}
}

func TestProviderCacheKeyCannotAliasAcrossWorkspaces(t *testing.T) {
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{Unwrapper: unwrapper})
	first := testEnvelope(t, "workspace-1", "cerebras", "workspace-1-secret")
	firstKey := Fingerprint("workspace-1", "cerebras", first)
	if _, _, err := cache.Resolve(
		t.Context(), "workspace-1", "cerebras", firstKey, first,
	); err != nil {
		t.Fatalf("prime cache: %v", err)
	}

	second := testEnvelope(t, "workspace-2", "cerebras", "workspace-2-secret")
	if _, _, err := cache.Resolve(
		t.Context(), "workspace-2", "cerebras", firstKey, second,
	); err == nil || !strings.Contains(err.Error(), "does not match envelope binding") {
		t.Fatalf("cross-workspace alias error = %v", err)
	}
	if unwrapper.calls != 1 {
		t.Fatalf("cross-workspace alias reached the DEK unwrapper; calls = %d", unwrapper.calls)
	}
}

func TestProviderCacheRejectsNULDelimitedIdentityBeforeUnwrap(t *testing.T) {
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{Unwrapper: unwrapper})
	envelope := testEnvelope(t, "workspace-1", "cerebras", "secret")

	if _, _, err := cache.Resolve(
		t.Context(), "workspace-1\x00cerebras", "", "", envelope,
	); err == nil || !strings.Contains(err.Error(), "contains a NUL byte") {
		t.Fatalf("NUL-delimited identity error = %v", err)
	}
	if unwrapper.calls != 0 {
		t.Fatalf("NUL-delimited identity reached the DEK unwrapper %d times", unwrapper.calls)
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

func TestResolveBoundsCachedPlaintextEntries(t *testing.T) {
	now := time.Unix(100, 0)
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{
		TTL:        time.Hour,
		MaxEntries: 2,
		Unwrapper:  unwrapper,
		Now:        func() time.Time { return now },
	})

	for _, provider := range []string{"first", "second", "third"} {
		envelope := testEnvelope(t, "workspace-1", provider, provider+"-secret")
		if _, _, err := cache.Resolve(
			t.Context(),
			"workspace-1",
			provider,
			Fingerprint("workspace-1", provider, envelope),
			envelope,
		); err != nil {
			t.Fatalf("Resolve(%s): %v", provider, err)
		}
	}

	if got := cache.Size(); got != 2 {
		t.Fatalf("cache size = %d, want 2", got)
	}
	first := testEnvelope(t, "workspace-1", "first", "first-secret")
	_, cached, err := cache.Resolve(
		t.Context(),
		"workspace-1",
		"first",
		Fingerprint("workspace-1", "first", first),
		first,
	)
	if err != nil {
		t.Fatalf("Resolve(evicted): %v", err)
	}
	if cached {
		t.Fatal("oldest plaintext entry was not evicted")
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
		Algorithm:    AlgorithmV2,
		KeyRef:       "projects/test/locations/us/keyRings/tr/cryptoKeys/byok",
		EncryptedDEK: "wrapped-dek",
		DEKNonce:     "dek-nonce-123",
		Ciphertext:   "ciphertext",
		Nonce:        "nonce",
	}
	got := Fingerprint("workspace-1", "cerebras", envelope)
	want := "byokcache:v1:e490fdd7a7a46f4b1bc885a65657de443f9963895ef2054d51310935b70dccd4"
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
	aad, err := aadV2(namespaceProvider, workspaceID, provider)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), aad)
	return EncryptedSecretEnvelope{
		Algorithm:    AlgorithmV2,
		KeyRef:       "projects/test/locations/us/keyRings/tr/cryptoKeys/byok",
		EncryptedDEK: base64.URLEncoding.EncodeToString([]byte("wrapped-dek")),
		DEKNonce:     base64.URLEncoding.EncodeToString([]byte("dek-nonce-123")),
		Ciphertext:   base64.URLEncoding.EncodeToString(ciphertext),
		Nonce:        base64.URLEncoding.EncodeToString(nonce),
	}
}
