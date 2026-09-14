package phalaaci

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const Suite = "x25519-aes-256-gcm-hkdf-sha256"

type Encryption struct {
	Private   *ecdh.PrivateKey
	Server    *ecdh.PublicKey
	Model     string
	Nonce     string
	Timestamp int64
}

func NewEncryption(proof *Proof, nonce string, timestamp int64) (*Encryption, error) {
	var selected string
	for _, key := range proof.Keyset.EncryptionKeys {
		if key.Algo == Suite {
			if selected != "" {
				return nil, errors.New("ACI ambiguous encryption keys")
			}
			selected = key.PublicKey
		}
	}
	if !IsHex(selected, 32) || !IsHex(nonce, 32) || timestamp <= 0 {
		return nil, errors.New("ACI invalid encryption context")
	}
	raw, _ := hex.DecodeString(selected)
	server, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, err
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// ECDH rejects low-order public keys, before any content is transmitted.
	if _, err := private.ECDH(server); err != nil {
		return nil, errors.New("ACI low-order encryption key")
	}
	return &Encryption{Private: private, Server: server, Model: proof.Model, Nonce: nonce, Timestamp: timestamp}, nil
}

func (e *Encryption) AAD(field, responseID string, response bool) ([]byte, error) {
	value := map[string]any{"algo": Suite, "model": e.Model, "field": field, "nonce": e.Nonce, "ts": e.Timestamp}
	if response {
		value["purpose"] = "aci.e2ee.response.v2"
		value["id"] = responseID
	} else {
		value["purpose"] = "aci.e2ee.request.v2"
	}
	return CanonicalValue(value)
}

func sharedCipher(private *ecdh.PrivateKey, public *ecdh.PublicKey) (cipher.AEAD, error) {
	secret, err := private.ECDH(public)
	if err != nil {
		return nil, errors.New("ACI invalid ECDH peer")
	}
	defer clear(secret)
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte("aci.e2ee.v2.x25519")), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func EncryptField(recipient *ecdh.PublicKey, plaintext, aad []byte) (string, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	aead, err := sharedCipher(ephemeral, recipient)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	result := append(ephemeral.PublicKey().Bytes(), nonce...)
	result = aead.Seal(result, nonce, plaintext, aad)
	return hex.EncodeToString(result), nil
}

func DecryptField(private *ecdh.PrivateKey, encoded string, aad []byte) ([]byte, error) {
	if len(encoded) > MaxArtifactBytes*2 {
		return nil, errors.New("ACI encrypted field too large")
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) < 32+12+16 {
		return nil, errors.New("ACI field is not authenticated ciphertext")
	}
	peer, err := ecdh.X25519().NewPublicKey(raw[:32])
	if err != nil {
		return nil, err
	}
	aead, err := sharedCipher(private, peer)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, raw[32:44], raw[44:], aad)
	if err != nil {
		return nil, errors.New("ACI field authentication failed")
	}
	return plaintext, nil
}
