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
	JWK             JWK    `json:"jwk"`
	Attestation     string `json:"att,omitempty"`
	AttestationKind string `json:"att_kind,omitempty"`
}

// JWK is the public Ed25519 signing key in receipt protected-header form.
type JWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
}

type flattenedJWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// JWSParts is the format-only result of parsing a compact or flattened JWS.
// Relying parties must apply their own header, key, signature, and claims
// policy; in particular, they must not trust an embedded JWK merely because it
// was decoded here.
type JWSParts struct {
	ProtectedJSON []byte
	PayloadJSON   []byte
	Signature     []byte
	SigningInput  []byte
}

// NewSigner generates a fresh Ed25519 keypair from crypto/rand.
func NewSigner() (*Signer, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("receipt: generate signing key: %w", err)
	}
	return &Signer{publicKey: publicKey, privateKey: privateKey}, nil
}

// NewSignerFromSeed builds a deterministic signer from a 32-byte Ed25519
// seed. It exists for parity-fixture generation and cross-implementation
// tests only; the enclave boot path always uses NewSigner's crypto/rand key.
func NewSignerFromSeed(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("receipt: seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("receipt: derived public key has unexpected type")
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

// JWK returns the public half of the signing key in receipt protected-header
// form. It contains no private key material.
func (s *Signer) JWK() JWK {
	return JWK{
		KeyType: "OKP",
		Curve:   "Ed25519",
		X:       rawBase64.EncodeToString(s.publicKey),
	}
}

// SignDigest signs one already-domain-separated SHA-256 digest with the
// boot-local receipt key. It exists for protocols that bind the same attested
// boot identity without exposing or serializing the private key.
func (s *Signer) SignDigest(digest [sha256.Size]byte) ([]byte, error) {
	if s == nil || len(s.privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("receipt: signer is not initialized")
	}
	return ed25519.Sign(s.privateKey, digest[:]), nil
}

// SignMessage signs an exact protocol message with the boot-local receipt key.
// It is intentionally narrower than exposing the private key: callers retain
// ownership of their domain separation and serialization, while the attested
// key remains enclave-local. Compact JWS protocols use this because EdDSA signs
// the protected64 + "." + payload64 bytes directly, not a caller-hashed digest.
func (s *Signer) SignMessage(message []byte) ([]byte, error) {
	if s == nil || len(s.privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("receipt: signer is not initialized")
	}
	return ed25519.Sign(s.privateKey, message), nil
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
	attestationValue, err := EncodeAttestation(attDoc, attKind)
	if err != nil {
		return nil, err
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

// EncodeAttestation returns an attestation document in the exact string form
// used by a flattened receipt's protected header. JWTs remain verbatim while
// binary Nitro COSE documents use unpadded base64url.
func EncodeAttestation(attDoc []byte, attKind string) (string, error) {
	if len(attDoc) == 0 {
		return "", errors.New("receipt: attestation document is required")
	}
	switch attKind {
	case "gcp-cs-jwt", "azure-maa-jwt":
		return string(attDoc), nil
	case "aws-nitro-cose":
		return rawBase64.EncodeToString(attDoc), nil
	default:
		return "", fmt.Errorf("receipt: unsupported attestation kind %q", attKind)
	}
}

func (s *Signer) sign(claims Claims, additions protectedHeader) (string, string, string, error) {
	if s == nil || len(s.publicKey) != ed25519.PublicKeySize || len(s.privateKey) != ed25519.PrivateKeySize {
		return "", "", "", errors.New("receipt: signer is not initialized")
	}
	header := protectedHeader{
		Algorithm:       "EdDSA",
		Type:            receiptType,
		KID:             s.Kid(),
		JWK:             s.JWK(),
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
	parts, err := ParseJWS(serialized)
	if err != nil {
		return err
	}
	var header protectedHeader
	if err := json.Unmarshal(parts.ProtectedJSON, &header); err != nil {
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
	if !ed25519.Verify(ed25519.PublicKey(publicKey), parts.SigningInput, parts.Signature) {
		return errors.New("receipt: signature verification failed")
	}
	return nil
}

// ParseJWS decodes JWS serialization and base64url fields without making any
// trust decision. This is the receipt package's reusable FORMAT seam.
func ParseJWS(serialized []byte) (JWSParts, error) {
	var protected, payload, signature string
	trimmed := strings.TrimSpace(string(serialized))
	if strings.HasPrefix(trimmed, "{") {
		var flattened flattenedJWS
		if err := json.Unmarshal([]byte(trimmed), &flattened); err != nil {
			return JWSParts{}, fmt.Errorf("receipt: unmarshal flattened JWS: %w", err)
		}
		protected, payload, signature = flattened.Protected, flattened.Payload, flattened.Signature
	} else {
		parts := strings.Split(trimmed, ".")
		if len(parts) != 3 {
			return JWSParts{}, fmt.Errorf("receipt: compact JWS has %d parts", len(parts))
		}
		protected, payload, signature = parts[0], parts[1], parts[2]
	}
	headerJSON, err := rawBase64.DecodeString(protected)
	if err != nil {
		return JWSParts{}, fmt.Errorf("receipt: decode protected header: %w", err)
	}
	payloadJSON, err := rawBase64.DecodeString(payload)
	if err != nil {
		return JWSParts{}, fmt.Errorf("receipt: decode payload: %w", err)
	}
	signatureBytes, err := rawBase64.DecodeString(signature)
	if err != nil {
		return JWSParts{}, fmt.Errorf("receipt: decode signature: %w", err)
	}
	return JWSParts{
		ProtectedJSON: headerJSON,
		PayloadJSON:   payloadJSON,
		Signature:     signatureBytes,
		SigningInput:  []byte(protected + "." + payload),
	}, nil
}
