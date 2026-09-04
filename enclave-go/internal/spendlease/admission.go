package spendlease

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
)

type MessageSigner interface {
	Kid() string
	SignMessage([]byte) ([]byte, error)
}

type admissionProtectedHeader struct {
	Algorithm string `json:"alg"`
	KID       string `json:"kid"`
	Type      string `json:"typ"`
}

func SignAdmissionReceipt(signer MessageSigner, claims AdmissionReceiptClaims) (string, error) {
	if signer == nil || signer.Kid() == "" {
		return "", errors.New("spendlease: admission receipt signer is unavailable")
	}
	if claims.Version != 1 || claims.BootKID == "" || claims.BootKID != signer.Kid() {
		return "", errors.New("spendlease: invalid admission receipt claims")
	}
	headerJSON, err := json.Marshal(admissionProtectedHeader{
		Algorithm: "EdDSA", Type: AdmissionJWSType, KID: signer.Kid(),
	})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	protected := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := []byte(protected + "." + payload)
	signature, err := signer.SignMessage(signingInput)
	if err != nil {
		return "", err
	}
	return string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func AdmissionReceiptHash(receipt string) string {
	digest := sha256.Sum256([]byte(receipt))
	return hex.EncodeToString(digest[:])
}

func IdempotencyKeyHash(idempotencyKey string) string {
	digest := sha256.Sum256([]byte(idempotencyKey))
	return hex.EncodeToString(digest[:])
}
