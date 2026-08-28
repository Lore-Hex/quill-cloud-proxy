package spendlease

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const authorizeDomain = "tr-authorize-v1"

const BootAuthHeader = "X-TR-Boot-Auth"

const issuerConfigDomain = "spend-lease-issuer-config-v1"

type DigestSigner interface {
	Kid() string
	SignDigest([sha256.Size]byte) ([]byte, error)
}

// IssuerConfigCommitment is carried as an attestation nonce so registration
// proves the exact Secret Manager manifest bytes the verifier loaded.
func IssuerConfigCommitment(config []byte) [sha256.Size]byte {
	preimage := make([]byte, 0, len(issuerConfigDomain)+1+len(config))
	preimage = append(preimage, issuerConfigDomain...)
	preimage = append(preimage, 0)
	preimage = append(preimage, config...)
	return sha256.Sum256(preimage)
}

// AuthorizeDigest covers the exact serialized body bytes sent on the wire.
func AuthorizeDigest(method, path string, body []byte) [sha256.Size]byte {
	bodyDigest := sha256.Sum256(body)
	preimage := make([]byte, 0, len(authorizeDomain)+len(method)+len(path)+sha256.Size)
	preimage = append(preimage, authorizeDomain...)
	preimage = append(preimage, strings.ToUpper(method)...)
	preimage = append(preimage, path...)
	preimage = append(preimage, bodyDigest[:]...)
	return sha256.Sum256(preimage)
}

func SignAuthorize(signer DigestSigner, method, path string, body []byte) (BootAuth, error) {
	if signer == nil || signer.Kid() == "" {
		return BootAuth{}, errors.New("spendlease: boot signer is unavailable")
	}
	digest := AuthorizeDigest(method, path, body)
	signature, err := signer.SignDigest(digest)
	if err != nil {
		return BootAuth{}, err
	}
	return BootAuth{KID: signer.Kid(), Sig: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func (auth BootAuth) HeaderValue() string {
	return "kid=" + auth.KID + ",sig=" + auth.Sig
}
