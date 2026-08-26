// Package receipt signs inference receipts with an enclave-local Ed25519 key.
package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	receiptType         = "inference-receipt+jws"
	keyCommitmentDomain = "inference-receipt-key-v1"
)

var rawBase64 = base64.RawURLEncoding

// Signer owns one per-instance signing key. The private key has deliberately
// no accessor or serialization path and remains in enclave memory only.
type Signer struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// Claims is the signed inference-receipt/1 payload. Declaration order is the
// wire order because JWS signs the exact json.Marshal output.
type Claims struct {
	RV         int            `json:"rv"`
	Issuer     string         `json:"iss"`
	IssuedAt   int64          `json:"iat"`
	JTI        string         `json:"jti"`
	Generation string         `json:"gen,omitempty"`
	Nonce      string         `json:"nonce,omitempty"`
	Route      string         `json:"route"`
	Request    HashRecord     `json:"req"`
	Response   ResponseRecord `json:"resp"`
	Model      Model          `json:"model"`
	Upstream   Upstream       `json:"upstream"`
	AttSHA256  string         `json:"att_sha256,omitempty"`
}

// HashRecord identifies the byte domain and digest of a request.
type HashRecord struct {
	Algorithm string `json:"alg"`
	Hash      string `json:"hash"`
	Of        string `json:"of"`
}

// ResponseRecord identifies the byte domain and digest of a response. Events
// is a pointer so a zero-event stream can include events:0 while buffered
// response claims can omit the field.
type ResponseRecord struct {
	Algorithm string `json:"alg"`
	Hash      string `json:"hash"`
	Of        string `json:"of"`
	Events    *int   `json:"events,omitempty"`
}

// Model records the router's exact model selection metadata.
type Model struct {
	Requested string `json:"requested"`
	Selected  string `json:"selected"`
	Provider  string `json:"provider"`
	Endpoint  string `json:"endpoint"`
}

// Upstream records the verification mechanism applied to the upstream used
// for this request. Tier-specific fields are omitted when they do not apply.
type Upstream struct {
	Tier                  string `json:"tier"`
	Policy                string `json:"policy,omitempty"`
	VerifiedAt            int64  `json:"verified_at,omitempty"`
	VerificationExpiresAt int64  `json:"verification_expires_at,omitempty"`
	CertSHA256            string `json:"cert_sha256,omitempty"`
}

type protectedHeader struct {
	Algorithm       string `json:"alg"`
	Type            string `json:"typ"`
	KID             string `json:"kid"`
	JWK             jwk    `json:"jwk"`
	Attestation     string `json:"att,omitempty"`
	AttestationKind string `json:"att_kind,omitempty"`
}

type jwk struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
}

type flattenedJWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// NewSigner generates a fresh Ed25519 keypair from crypto/rand.
func NewSigner() (*Signer, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("receipt: generate signing key: %w", err)
	}
	return &Signer{publicKey: publicKey, privateKey: privateKey}, nil
}

// KeyCommitment returns SHA-256("inference-receipt-key-v1" || 0x00 || pubkey).
func (s *Signer) KeyCommitment() [32]byte {
	preimage := make([]byte, 0, len(keyCommitmentDomain)+1+ed25519.PublicKeySize)
	preimage = append(preimage, keyCommitmentDomain...)
	preimage = append(preimage, 0)
	preimage = append(preimage, s.publicKey...)
	return sha256.Sum256(preimage)
}

// Kid returns the unpadded base64url SHA-256 digest of the raw public key.
func (s *Signer) Kid() string {
	digest := sha256.Sum256(s.publicKey)
	return rawBase64.EncodeToString(digest[:])
}

// SignCompact signs claims as a compact JWS without embedded attestation.
func (s *Signer) SignCompact(claims Claims) (string, error) {
	protected, payload, signature, err := s.sign(claims, protectedHeader{})
	if err != nil {
		return "", err
	}
	return protected + "." + payload + "." + signature, nil
}

// SignFlattened signs claims as flattened JWS JSON and embeds attestation
// material in the protected header. JWT attestations are embedded verbatim;
// the binary Nitro COSE document is base64url-encoded.
func (s *Signer) SignFlattened(claims Claims, attDoc []byte, attKind string) ([]byte, error) {
	if len(attDoc) == 0 {
		return nil, errors.New("receipt: attestation document is required")
	}
	var attestationValue string
	switch attKind {
	case "gcp-cs-jwt", "azure-maa-jwt":
		attestationValue = string(attDoc)
	case "aws-nitro-cose":
		attestationValue = rawBase64.EncodeToString(attDoc)
	default:
		return nil, fmt.Errorf("receipt: unsupported attestation kind %q", attKind)
	}
	protected, payload, signature, err := s.sign(claims, protectedHeader{
		Attestation:     attestationValue,
		AttestationKind: attKind,
	})
	if err != nil {
		return nil, err
	}
	serialized, err := json.Marshal(flattenedJWS{
		Protected: protected,
		Payload:   payload,
		Signature: signature,
	})
	if err != nil {
		return nil, fmt.Errorf("receipt: marshal flattened JWS: %w", err)
	}
	return serialized, nil
}

func (s *Signer) sign(claims Claims, additions protectedHeader) (string, string, string, error) {
	if s == nil || len(s.publicKey) != ed25519.PublicKeySize || len(s.privateKey) != ed25519.PrivateKeySize {
		return "", "", "", errors.New("receipt: signer is not initialized")
	}
	header := protectedHeader{
		Algorithm: "EdDSA",
		Type:      receiptType,
		KID:       s.Kid(),
		JWK: jwk{
			KeyType: "OKP",
			Curve:   "Ed25519",
			X:       rawBase64.EncodeToString(s.publicKey),
		},
		Attestation:     additions.Attestation,
		AttestationKind: additions.AttestationKind,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", "", "", fmt.Errorf("receipt: marshal protected header: %w", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", "", "", fmt.Errorf("receipt: marshal claims: %w", err)
	}
	protected := rawBase64.EncodeToString(headerJSON)
	payload := rawBase64.EncodeToString(payloadJSON)
	signingInput := protected + "." + payload
	signature := ed25519.Sign(s.privateKey, []byte(signingInput))
	return protected, payload, rawBase64.EncodeToString(signature), nil
}

// Verify verifies either compact or flattened JWS produced by Signer. It is a
// small test helper, not a relying-party attestation or claims verifier.
func Verify(serialized []byte) error {
	var protected, payload, signature string
	trimmed := strings.TrimSpace(string(serialized))
	if strings.HasPrefix(trimmed, "{") {
		var flattened flattenedJWS
		if err := json.Unmarshal([]byte(trimmed), &flattened); err != nil {
			return fmt.Errorf("receipt: unmarshal flattened JWS: %w", err)
		}
		protected, payload, signature = flattened.Protected, flattened.Payload, flattened.Signature
	} else {
		parts := strings.Split(trimmed, ".")
		if len(parts) != 3 {
			return fmt.Errorf("receipt: compact JWS has %d parts", len(parts))
		}
		protected, payload, signature = parts[0], parts[1], parts[2]
	}
	headerJSON, err := rawBase64.DecodeString(protected)
	if err != nil {
		return fmt.Errorf("receipt: decode protected header: %w", err)
	}
	var header protectedHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("receipt: unmarshal protected header: %w", err)
	}
	if header.Algorithm != "EdDSA" || header.Type != receiptType || header.JWK.KeyType != "OKP" || header.JWK.Curve != "Ed25519" {
		return errors.New("receipt: unsupported protected header")
	}
	publicKey, err := rawBase64.DecodeString(header.JWK.X)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("receipt: invalid Ed25519 public key")
	}
	digest := sha256.Sum256(publicKey)
	if header.KID != rawBase64.EncodeToString(digest[:]) {
		return errors.New("receipt: kid does not match public key")
	}
	signatureBytes, err := rawBase64.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("receipt: decode signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(protected+"."+payload), signatureBytes) {
		return errors.New("receipt: signature verification failed")
	}
	return nil
}
