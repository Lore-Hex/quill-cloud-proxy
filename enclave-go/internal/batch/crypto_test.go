package batch

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type fakeKMS struct {
	wrappedAAD   []byte
	unwrappedAAD []byte
	failWrap     bool
	failUnwrap   bool
}

func (k *fakeKMS) WrapDEK(_ context.Context, _ string, plaintext, aad []byte) ([]byte, error) {
	if k.failWrap {
		return nil, errors.New("wrap failed")
	}
	k.wrappedAAD = append([]byte(nil), aad...)
	out := append([]byte("wrapped:"), plaintext...)
	return out, nil
}

func (k *fakeKMS) UnwrapDEK(_ context.Context, _ string, wrapped, aad []byte) ([]byte, error) {
	if k.failUnwrap {
		return nil, errors.New("unwrap failed")
	}
	k.unwrappedAAD = append([]byte(nil), aad...)
	if !bytes.HasPrefix(wrapped, []byte("wrapped:")) {
		return nil, errors.New("bad wrapped key")
	}
	return append([]byte(nil), wrapped[len("wrapped:"):]...), nil
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
	opened, err := protector.Open(t.Context(), "batch_0123456789abcdef0123456789abcdef", "input", encoded)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %q", opened)
	}
	if !bytes.Equal(kms.wrappedAAD, kms.unwrappedAAD) || !bytes.Contains(kms.wrappedAAD, []byte(":input")) {
		t.Fatalf("AAD mismatch: wrapped=%q unwrapped=%q", kms.wrappedAAD, kms.unwrappedAAD)
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
