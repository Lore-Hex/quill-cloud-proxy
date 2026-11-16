package awssealed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
)

func fixture(t *testing.T, region string, version uint64) (Response, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	bundle := Bundle{Nonce: make([]byte, 12), EncryptedDataKey: []byte("test-only opaque KMS key")}
	if _, err := rand.Read(bundle.Nonce); err != nil {
		t.Fatal(err)
	}
	bundle.Manifest = Manifest{Region: region, Version: version}
	aad, _ := bundle.Manifest.aad()
	bundle.Ciphertext = gcm.Seal(nil, bundle.Nonce, []byte(`{"region":"`+region+`","test":true}`), aad)
	bundle.Manifest.EncryptedDataKeySHA384 = digest(bundle.EncryptedDataKey)
	bundle.Manifest.CiphertextSHA384 = digest(append(bytes.Clone(bundle.Nonce), bundle.Ciphertext...))
	sign(t, &bundle, signer)
	return Response{Bundle: bundle, CiphertextForRecipient: []byte("test-only CMS input")}, signer, key
}

func sign(t *testing.T, bundle *Bundle, signer *ecdsa.PrivateKey) {
	t.Helper()
	hash, err := SigningDigest(bundle.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature, err = ecdsa.SignASN1(rand.Reader, signer, hash)
	if err != nil {
		t.Fatal(err)
	}
}

func encoded(t *testing.T, response Response) []byte {
	t.Helper()
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestValidBundlesAndGenuineCrossRegionAreAccepted(t *testing.T) {
	for _, region := range []string{"eu-west-1", "eu-west-3"} {
		response, signer, key := fixture(t, region, 4)
		releasedKey := bytes.Clone(key)
		plaintext, m, err := Open(encoded(t, response), &signer.PublicKey, 4, func(cms []byte) ([]byte, error) {
			if !bytes.Equal(cms, response.CiphertextForRecipient) {
				t.Fatal("wrong recipient response")
			}
			return releasedKey, nil
		})
		if err != nil || m.Region != region || !bytes.Contains(plaintext, []byte(`"test":true`)) {
			t.Fatalf("valid bundle rejected: %v", err)
		}
		if !bytes.Equal(releasedKey, make([]byte, 32)) {
			t.Fatal("released content key was not cleared")
		}
	}
}

func TestUnauthenticatedBundleNeverReachesRecipientUnwrap(t *testing.T) {
	mutations := map[string]func(*Response){
		"signature":          func(r *Response) { r.Bundle.Signature[0] ^= 1 },
		"no signature":       func(r *Response) { r.Bundle.Signature = nil },
		"old version":        func(r *Response) { r.Bundle.Manifest.Version = 1 },
		"new version forged": func(r *Response) { r.Bundle.Manifest.Version = 50 },
		"region forged":      func(r *Response) { r.Bundle.Manifest.Region = "eu-west-3" },
		"unknown region":     func(r *Response) { r.Bundle.Manifest.Region = "us-east-1" },
		"key blob":           func(r *Response) { r.Bundle.EncryptedDataKey[0] ^= 1 },
		"nonce":              func(r *Response) { r.Bundle.Nonce[0] ^= 1 },
		"ciphertext":         func(r *Response) { r.Bundle.Ciphertext[0] ^= 1 },
		"bad nonce length":   func(r *Response) { r.Bundle.Nonce = r.Bundle.Nonce[:11] },
		"oversized CMS":      func(r *Response) { r.CiphertextForRecipient = make([]byte, MaxCMSBytes+1) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			response, signer, _ := fixture(t, "eu-west-1", 4)
			mutate(&response)
			plain, _, err := Open(encoded(t, response), &signer.PublicKey, 4, func([]byte) ([]byte, error) {
				t.Fatal("unauthenticated or malformed data reached unwrap")
				return nil, nil
			})
			if err == nil || len(plain) != 0 {
				t.Fatal("bad bundle accepted")
			}
		})
	}
}

func TestParentChosenKeyAndCiphertextCannotForgeConfiguration(t *testing.T) {
	legitimate, signer, _ := fixture(t, "eu-west-1", 4)
	forged, _, attackerKey := fixture(t, "eu-west-1", 4)
	forged.Bundle.Signature = legitimate.Bundle.Signature
	plain, _, err := Open(encoded(t, forged), &signer.PublicKey, 4, func([]byte) ([]byte, error) {
		t.Fatal("parent forgery reached unwrap")
		return bytes.Clone(attackerKey), nil
	})
	if err == nil || len(plain) != 0 {
		t.Fatal("parent-signed configuration accepted")
	}
}

func TestWrongUnwrappedKeyFailsEvenWithAuthenticBundle(t *testing.T) {
	response, signer, _ := fixture(t, "eu-west-1", 4)
	for _, length := range []int{0, 16, 24, 32, 64} {
		plain, _, err := Open(encoded(t, response), &signer.PublicKey, 4, func([]byte) ([]byte, error) {
			return make([]byte, length), nil
		})
		if err == nil || len(plain) != 0 {
			t.Fatalf("wrong recipient key of length %d accepted", length)
		}
	}
	_, _, err := Open(encoded(t, response), &signer.PublicKey, 4, func([]byte) ([]byte, error) {
		return nil, errors.New("must not leak upstream content")
	})
	if err == nil || bytes.Contains([]byte(err.Error()), []byte("leak upstream")) {
		t.Fatal("unwrap error was missing or leaked data")
	}
}

func TestCanonicalFormatRejectsAmbiguousAndUnboundedJSON(t *testing.T) {
	response, signer, key := fixture(t, "eu-west-1", 4)
	valid := encoded(t, response)
	inputs := [][]byte{
		append(bytes.Clone(valid), '\n'),
		append(bytes.Clone(valid), valid...),
		bytes.Replace(valid, []byte(`"version":4`), []byte(`"version":4,"version":4`), 1),
		bytes.Replace(valid, []byte(`"version":4`), []byte(`"Version":4`), 1),
		bytes.Replace(valid, []byte(`"version":4`), []byte(`"version":4,"unknown":true`), 1),
		bytes.Replace(valid, []byte(`"version":4`), []byte(`"version":4.0`), 1),
		bytes.Repeat([]byte(" "), MaxResponseBytes+1),
	}
	for _, data := range inputs {
		plain, _, err := Open(data, &signer.PublicKey, 4, func([]byte) ([]byte, error) {
			t.Fatal("noncanonical input reached unwrap")
			return bytes.Clone(key), nil
		})
		if err == nil || len(plain) != 0 {
			t.Fatal("noncanonical input accepted")
		}
	}
}

func TestPinnedSignerAndMinimumAreMandatory(t *testing.T) {
	response, signer, key := fixture(t, "eu-west-1", 4)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, pub := range []*ecdsa.PublicKey{nil, {}, &other.PublicKey} {
		if _, _, err := Open(encoded(t, response), pub, 4, func([]byte) ([]byte, error) { return bytes.Clone(key), nil }); err == nil {
			t.Fatal("invalid pinned signer accepted")
		}
	}
	if _, _, err := Open(encoded(t, response), &signer.PublicKey, 0, func([]byte) ([]byte, error) { return bytes.Clone(key), nil }); err == nil {
		t.Fatal("zero minimum accepted")
	}
}

func FuzzBundleParser(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"bundle":null,"ciphertext_for_recipient":null}`))
	signer, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxResponseBytes+1 {
			return
		}
		_, _, _ = Open(data, &signer.PublicKey, 1, func([]byte) ([]byte, error) { return nil, errors.New("test") })
	})
}
