package batch

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

const encryptedArtifactVersion = 1

type KMS interface {
	WrapDEK(context.Context, string, []byte, []byte) ([]byte, error)
	UnwrapDEK(context.Context, string, []byte, []byte) ([]byte, error)
}

type Protector interface {
	Seal(context.Context, string, string, []byte) ([]byte, error)
	Open(context.Context, string, string, []byte) ([]byte, error)
}

type EnvelopeProtector struct {
	KMS     KMS
	KeyName string
	Rand    io.Reader
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
	random := p.Rand
	if random == nil {
		random = rand.Reader
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(random, dek); err != nil {
		return nil, fmt.Errorf("batch encryption key: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, fmt.Errorf("batch encryption nonce: %w", err)
	}
	aad := artifactAAD(batchID, kind)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	wrapped, err := p.KMS.WrapDEK(ctx, p.KeyName, dek, aad)
	for i := range dek {
		dek[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("batch wrap key: %w", err)
	}
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
	if artifact.Version != encryptedArtifactVersion || artifact.KMSKey == "" || artifact.KMSKey != p.KeyName {
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
	aad := artifactAAD(batchID, kind)
	dek, err := p.KMS.UnwrapDEK(ctx, artifact.KMSKey, wrapped, aad)
	if err != nil {
		return nil, fmt.Errorf("batch unwrap key: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()
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
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("batch ciphertext authentication failed")
	}
	return plaintext, nil
}

func artifactAAD(batchID, kind string) []byte {
	return []byte("trustedrouter:batch:v1:" + batchID + ":" + kind)
}
