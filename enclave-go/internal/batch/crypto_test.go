package batch

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeKMS struct {
	mu           sync.Mutex
	wrappedAAD   []byte
	unwrappedAAD []byte
	failWrap     bool
	failUnwrap   bool
	wrapCalls    int
	unwrapCalls  int
}

type concurrentWrapKMS struct {
	entered chan string
	release chan struct{}
}

func (k *concurrentWrapKMS) WrapDEK(_ context.Context, _ string, plaintext, aad []byte) ([]byte, error) {
	k.entered <- string(aad)
	<-k.release
	return append([]byte("wrapped:"), plaintext...), nil
}

func (k *concurrentWrapKMS) UnwrapDEK(_ context.Context, _ string, wrapped, _ []byte) ([]byte, error) {
	if !bytes.HasPrefix(wrapped, []byte("wrapped:")) {
		return nil, errors.New("bad wrapped key")
	}
	return append([]byte(nil), wrapped[len("wrapped:"):]...), nil
}

func (k *fakeKMS) WrapDEK(_ context.Context, _ string, plaintext, aad []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.wrapCalls++
	if k.failWrap {
		return nil, errors.New("wrap failed")
	}
	k.wrappedAAD = append([]byte(nil), aad...)
	out := append([]byte("wrapped:"), plaintext...)
	return out, nil
}

func (k *fakeKMS) UnwrapDEK(_ context.Context, _ string, wrapped, aad []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.unwrapCalls++
	if k.failUnwrap {
		return nil, errors.New("unwrap failed")
	}
	k.unwrappedAAD = append([]byte(nil), aad...)
	if !bytes.HasPrefix(wrapped, []byte("wrapped:")) {
		return nil, errors.New("bad wrapped key")
	}
	return append([]byte(nil), wrapped[len("wrapped:"):]...), nil
}

func (k *fakeKMS) calls() (int, int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.wrapCalls, k.unwrapCalls
}

func TestEnvelopeProtectorRoundTripAndNoPlaintext(t *testing.T) {
	t.Parallel()

	kms := &fakeKMS{}
	protector := &EnvelopeProtector{
		KMS:     kms,
		KeyName: "projects/p/locations/us/keyRings/r/cryptoKeys/batch",
		Rand:    bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)),
	}
	plaintext := []byte(`{"bearer":"sk-tr-secret","prompt":"private prompt"}`)
	encoded, err := protector.Seal(t.Context(), "batch_0123456789abcdef0123456789abcdef", "input", plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for _, secret := range [][]byte{[]byte("sk-tr-secret"), []byte("private prompt")} {
		if bytes.Contains(encoded, secret) {
			t.Fatalf("encrypted artifact contains plaintext %q", secret)
		}
	}
	// A fresh enclave instance must recover the same key from the artifact.
	restarted := &EnvelopeProtector{KMS: kms, KeyName: protector.KeyName}
	opened, err := restarted.Open(t.Context(), "batch_0123456789abcdef0123456789abcdef", "input", encoded)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %q", opened)
	}
	if !bytes.Equal(kms.wrappedAAD, kms.unwrappedAAD) || !bytes.Contains(kms.wrappedAAD, []byte("batch-key:v2")) {
		t.Fatalf("AAD mismatch: wrapped=%q unwrapped=%q", kms.wrappedAAD, kms.unwrappedAAD)
	}
}

func TestEnvelopeProtectorReusesOneKMSKeyPerActiveBatch(t *testing.T) {
	t.Parallel()

	kms := &fakeKMS{}
	protector := &EnvelopeProtector{KMS: kms, KeyName: "key"}
	artifacts := make([][]byte, 200)
	for index := range artifacts {
		encoded, err := protector.Seal(
			t.Context(), "batch_shared", fmt.Sprintf("result:%d", index), []byte("private"),
		)
		if err != nil {
			t.Fatalf("Seal(%d): %v", index, err)
		}
		artifacts[index] = encoded
	}
	wraps, unwraps := kms.calls()
	if wraps != 1 || unwraps != 0 {
		t.Fatalf("KMS calls after seal = wrap:%d unwrap:%d", wraps, unwraps)
	}

	restarted := &EnvelopeProtector{KMS: kms, KeyName: "key"}
	for index, encoded := range artifacts {
		opened, err := restarted.Open(
			t.Context(), "batch_shared", fmt.Sprintf("result:%d", index), encoded,
		)
		if err != nil || string(opened) != "private" {
			t.Fatalf("Open(%d) = %q, %v", index, opened, err)
		}
	}
	wraps, unwraps = kms.calls()
	if wraps != 1 || unwraps != 1 {
		t.Fatalf("KMS calls after restart = wrap:%d unwrap:%d", wraps, unwraps)
	}
}

func TestEnvelopeProtectorConcurrentFirstUseWrapsOnce(t *testing.T) {
	t.Parallel()

	kms := &fakeKMS{}
	protector := &EnvelopeProtector{KMS: kms, KeyName: "key"}
	var workers sync.WaitGroup
	errs := make(chan error, 64)
	for index := 0; index < 64; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			_, err := protector.Seal(
				t.Context(), "batch_concurrent", fmt.Sprintf("item:%d", index), []byte("private"),
			)
			errs <- err
		}(index)
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
	}
	wraps, _ := kms.calls()
	if wraps != 1 {
		t.Fatalf("wrap calls = %d, want 1", wraps)
	}
}

func TestEnvelopeProtectorDoesNotSerializeKMSAcrossBatches(t *testing.T) {
	t.Parallel()

	kms := &concurrentWrapKMS{
		entered: make(chan string, 2),
		release: make(chan struct{}),
	}
	protector := &EnvelopeProtector{KMS: kms, KeyName: "key"}
	errs := make(chan error, 2)
	for _, batchID := range []string{"batch_a", "batch_b"} {
		batchID := batchID
		go func() {
			_, err := protector.Seal(t.Context(), batchID, "input", []byte("private"))
			errs <- err
		}()
	}
	for range 2 {
		select {
		case <-kms.entered:
		case <-time.After(time.Second):
			close(kms.release)
			t.Fatal("KMS calls for independent batches were serialized")
		}
	}
	close(kms.release)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("Seal: %v", err)
		}
	}
}

func TestEnvelopeProtectorReadsLegacyPerArtifactEnvelope(t *testing.T) {
	t.Parallel()

	batchID := "batch_legacy"
	kind := "input"
	plaintext := []byte("private legacy payload")
	dek := bytes.Repeat([]byte{0x51}, 32)
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	nonce := bytes.Repeat([]byte{0x19}, aead.NonceSize())
	encoded, err := json.Marshal(encryptedArtifact{
		Version:    legacyEncryptedArtifactVersion,
		KMSKey:     "key",
		WrappedDEK: base64.StdEncoding.EncodeToString(append([]byte("wrapped:"), dek...)),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(
			nil, nonce, plaintext,
			artifactAAD(legacyEncryptedArtifactVersion, batchID, kind),
		)),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	kms := &fakeKMS{}
	protector := &EnvelopeProtector{KMS: kms, KeyName: "key"}
	opened, err := protector.Open(t.Context(), batchID, kind, encoded)
	if err != nil {
		t.Fatalf("Open legacy artifact: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %q", opened)
	}
	if !bytes.Equal(kms.unwrappedAAD, artifactAAD(legacyEncryptedArtifactVersion, batchID, kind)) {
		t.Fatalf("legacy unwrap AAD = %q", kms.unwrappedAAD)
	}
}

func TestEnvelopeProtectorBindsBatchAndArtifactKind(t *testing.T) {
	t.Parallel()

	protector := &EnvelopeProtector{
		KMS:     &fakeKMS{},
		KeyName: "key",
		Rand:    bytes.NewReader(bytes.Repeat([]byte{0x23}, 64)),
	}
	encoded, err := protector.Seal(t.Context(), "batch_0123456789abcdef0123456789abcdef", "input", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for _, test := range []struct{ batchID, kind string }{
		{"batch_1123456789abcdef0123456789abcdef", "input"},
		{"batch_0123456789abcdef0123456789abcdef", "results"},
	} {
		if _, err := protector.Open(t.Context(), test.batchID, test.kind, encoded); err == nil {
			t.Fatalf("Open(%q, %q) succeeded with wrong AAD", test.batchID, test.kind)
		}
	}
}

func TestEnvelopeProtectorRejectsTamperingAndKMSErrors(t *testing.T) {
	t.Parallel()

	kms := &fakeKMS{}
	protector := &EnvelopeProtector{KMS: kms, KeyName: "key", Rand: bytes.NewReader(bytes.Repeat([]byte{0x10}, 64))}
	encoded, err := protector.Seal(t.Context(), "batch_0123456789abcdef0123456789abcdef", "input", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	encoded[len(encoded)-3] ^= 1
	if _, err := protector.Open(t.Context(), "batch_0123456789abcdef0123456789abcdef", "input", encoded); err == nil {
		t.Fatal("Open accepted tampered artifact")
	}

	if _, err := (&EnvelopeProtector{KMS: &fakeKMS{failWrap: true}, KeyName: "key"}).Seal(t.Context(), "batch", "input", []byte("secret")); err == nil {
		t.Fatal("Seal accepted KMS wrap failure")
	}
	if _, err := (&EnvelopeProtector{KMS: &fakeKMS{failUnwrap: true}, KeyName: "key"}).Open(t.Context(), "batch", "input", []byte(`{"version":1,"kms_key":"key","wrapped_dek":"eA==","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"eA=="}`)); err == nil {
		t.Fatal("Open accepted KMS unwrap failure")
	}
}
