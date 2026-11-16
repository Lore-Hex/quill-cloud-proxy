// Package awssealed authenticates operator-sealed AWS bootstrap bundles.
// It does not fetch credentials, choose trust roots, or provide a legacy path.
package awssealed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	MaxBundleBytes   = 64 << 10
	MaxResponseBytes = 96 << 10
	MaxCMSBytes      = 16 << 10
	MaxPlainBytes    = 48 << 10
	signingDomain    = "trustedrouter.aws-bootstrap.v2\x00"
)

// Field order is the canonical JSON wire order, shared with the off-host
// sealer's sort_keys=True, separators=(",", ":"). Never sign arbitrary JSON.
type Manifest struct {
	CiphertextSHA384       string `json:"ciphertext_sha384"`
	EncryptedDataKeySHA384 string `json:"encrypted_data_key_sha384"`
	Region                 string `json:"region"`
	Version                uint64 `json:"version"`
}

type Bundle struct {
	Ciphertext       []byte   `json:"ciphertext"`
	EncryptedDataKey []byte   `json:"encrypted_data_key"`
	Manifest         Manifest `json:"manifest"`
	Nonce            []byte   `json:"nonce"`
	Signature        []byte   `json:"signature"`
}

type Response struct {
	Bundle                 Bundle `json:"bundle"`
	CiphertextForRecipient []byte `json:"ciphertext_for_recipient"`
}

func canonicalDecode(data []byte, limit int, target any) error {
	if len(data) == 0 || len(data) > limit {
		return errors.New("aws sealed bootstrap: message size")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return errors.New("aws sealed bootstrap: malformed JSON")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(data, canonical) {
		// This also rejects duplicate/unknown keys, alternate key casing,
		// missing/null scalar fields, noncanonical base64, and trailing data.
		return errors.New("aws sealed bootstrap: noncanonical JSON")
	}
	return nil
}

func digest(data []byte) string {
	sum := sha512.Sum384(data)
	return hex.EncodeToString(sum[:])
}

func (m Manifest) aad() ([]byte, error) {
	return json.Marshal(struct {
		Region  string `json:"region"`
		Version uint64 `json:"version"`
	}{m.Region, m.Version})
}

// SigningDigest is the SHA-384 digest supplied to KMS Sign with MessageType
// DIGEST and ECDSA_SHA_384. The domain separates this key's bootstrap use.
func SigningDigest(m Manifest) ([]byte, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	sum := sha512.Sum384(append([]byte(signingDomain), data...))
	return sum[:], nil
}

func validateBundle(bundle Bundle, signer *ecdsa.PublicKey, minimum uint64) error {
	if signer == nil || signer.Curve != elliptic.P384() || signer.X == nil || signer.Y == nil || !signer.Curve.IsOnCurve(signer.X, signer.Y) {
		return errors.New("aws sealed bootstrap: invalid pinned signer")
	}
	m := bundle.Manifest
	if minimum == 0 || m.Version < minimum || m.Version > 1<<53-1 {
		return errors.New("aws sealed bootstrap: bundle version")
	}
	if m.Region != "eu-west-1" && m.Region != "eu-west-3" {
		return errors.New("aws sealed bootstrap: bundle region")
	}
	if len(bundle.Nonce) != 12 || len(bundle.Ciphertext) < 16 || len(bundle.Ciphertext) > MaxPlainBytes+16 ||
		len(bundle.EncryptedDataKey) == 0 || len(bundle.EncryptedDataKey) > 6144 || len(bundle.Signature) > 128 {
		return errors.New("aws sealed bootstrap: bundle field size")
	}
	if len(m.CiphertextSHA384) != 96 || len(m.EncryptedDataKeySHA384) != 96 {
		return errors.New("aws sealed bootstrap: manifest hash length")
	}
	message, err := SigningDigest(m)
	if err != nil || !ecdsa.VerifyASN1(signer, message, bundle.Signature) {
		return errors.New("aws sealed bootstrap: signature rejected")
	}
	ciphertextDigest := sha512.New384()
	_, _ = ciphertextDigest.Write(bundle.Nonce)
	_, _ = ciphertextDigest.Write(bundle.Ciphertext)
	if hex.EncodeToString(ciphertextDigest.Sum(nil)) != m.CiphertextSHA384 || digest(bundle.EncryptedDataKey) != m.EncryptedDataKeySHA384 {
		return errors.New("aws sealed bootstrap: signed content hash mismatch")
	}
	encoded, err := json.Marshal(bundle)
	if err != nil || len(encoded) > MaxBundleBytes {
		return errors.New("aws sealed bootstrap: bundle exceeds Secrets Manager limit")
	}
	return nil
}

// Open authenticates before invoking the enclave's CMS recipient unwrap.
// unwrap must use the ephemeral private key bound into this boot's NSM
// document. Neither a returned key nor valid GCM alone authenticates a parent.
// Errors are fixed metadata; never include bootstrap content in an error/log.
func Open(data []byte, signer *ecdsa.PublicKey, minimum uint64, unwrap func([]byte) ([]byte, error)) ([]byte, Manifest, error) {
	var response Response
	if err := canonicalDecode(data, MaxResponseBytes, &response); err != nil {
		return nil, Manifest{}, err
	}
	if err := validateBundle(response.Bundle, signer, minimum); err != nil {
		return nil, Manifest{}, err
	}
	if unwrap == nil || len(response.CiphertextForRecipient) == 0 || len(response.CiphertextForRecipient) > MaxCMSBytes {
		return nil, Manifest{}, errors.New("aws sealed bootstrap: recipient ciphertext size")
	}
	key, err := unwrap(response.CiphertextForRecipient)
	defer clear(key)
	if err != nil || len(key) != 32 {
		return nil, Manifest{}, errors.New("aws sealed bootstrap: recipient unwrap rejected")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, Manifest{}, errors.New("aws sealed bootstrap: content key rejected")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, Manifest{}, errors.New("aws sealed bootstrap: GCM unavailable")
	}
	aad, err := response.Bundle.Manifest.aad()
	if err != nil {
		return nil, Manifest{}, errors.New("aws sealed bootstrap: associated data")
	}
	plaintext, err := gcm.Open(nil, response.Bundle.Nonce, response.Bundle.Ciphertext, aad)
	if err != nil {
		return nil, Manifest{}, errors.New("aws sealed bootstrap: ciphertext rejected")
	}
	return plaintext, response.Bundle.Manifest, nil
}
