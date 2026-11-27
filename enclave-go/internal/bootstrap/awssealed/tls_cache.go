package awssealed

import (
	"context"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

const TLSCacheProtocol = "trustedrouter.aws-tls-cache.v1"

var errTLSKey = errors.New("aws TLS cache: approved recipient key unavailable")

// The parent can construct a CMS message for any public RSA recipient. The
// measured commitment to the KMS-generated public key authenticates its secret
// counterpart. Neither a parent assertion nor successful CMS decryption does.
func FetchTLSCacheKey(ctx context.Context, dial Dialer, attest Attester, spkiHash string) ([]byte, error) {
	pin, err := hex.DecodeString(spkiHash)
	if err != nil || len(pin) != sha256.Size || hex.EncodeToString(pin) != spkiHash {
		return nil, errTLSKey
	}
	data, priv, err := recipientExchange(ctx, dial, attest, TLSCacheProtocol)
	if err != nil {
		return nil, errTLSKey
	}
	var response struct {
		CMS []byte `json:"ciphertext_for_recipient"`
	}
	if canonicalDecode(data, MaxResponseBytes, &response) != nil {
		return nil, errTLSKey
	}
	return openTLSCacheKey(response.CMS, priv, pin)
}

func openTLSCacheKey(cms []byte, priv *rsa.PrivateKey, pin []byte) ([]byte, error) {
	w, iv, ct, err := parseBoundedCMS(cms, aes.BlockSize, 256)
	if err != nil {
		return nil, errTLSKey
	}
	buf, err := decryptCMSBlocks(w, iv, ct, priv)
	if err != nil {
		return nil, errTLSKey
	}
	defer clear(buf)
	pad := int(buf[len(buf)-1])
	valid := subtle.ConstantTimeLessOrEq(1, pad) & subtle.ConstantTimeLessOrEq(pad, aes.BlockSize)
	for i := 1; i <= aes.BlockSize; i++ {
		valid &= subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(i, pad), subtle.ConstantTimeByteEq(buf[len(buf)-i], byte(pad)), 1)
	}
	if valid != 1 {
		return nil, errTLSKey
	}
	k, err := x509.ParsePKCS8PrivateKey(buf[:len(buf)-pad])
	ec, ok := k.(*ecdsa.PrivateKey)
	if err != nil || !ok || ec.Curve != elliptic.P256() {
		return nil, errTLSKey
	}
	scalar, err := ec.Bytes()
	if err != nil {
		return nil, errTLSKey
	}
	defer clear(scalar)
	// Derive the public point from the scalar, never trust an included point.
	key, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return nil, errTLSKey
	}
	der, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	hash := sha256.Sum256(der)
	if err != nil || subtle.ConstantTimeCompare(hash[:], pin) != 1 {
		return nil, errTLSKey
	}
	return hkdf.Key(sha256.New, scalar, hash[:], TLSCacheProtocol+"/wrapping-key", 32)
}
