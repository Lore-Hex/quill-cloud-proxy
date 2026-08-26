package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignCompactVerifyRoundTrip(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	compact, err := signer.SignCompact(testClaims())
	if err != nil {
		t.Fatalf("SignCompact: %v", err)
	}
	if err := Verify([]byte(compact)); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	parts := strings.Split(compact, ".")
	protectedJSON, err := rawBase64.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode protected header: %v", err)
	}
	if bytes.Contains(protectedJSON, []byte(`"att"`)) || bytes.Contains(protectedJSON, []byte(`"att_kind"`)) {
		t.Fatalf("compact protected header embeds attestation: %s", protectedJSON)
	}
}

func TestClaimsMarshalUsesSpecifiedNamesAndOrder(t *testing.T) {
	encoded, err := json.Marshal(testClaims())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"rv":1,"iss":"https://api.trustedrouter.com","iat":1756223999,"jti":"chatcmpl-test","gen":"gen-test","nonce":"nonce_test","route":"chat.completions","req":{"alg":"sha256","hash":"request","of":"body"},"resp":{"alg":"sha256","hash":"response","of":"sse-data-v1","events":0},"model":{"requested":"requested","selected":"selected","provider":"provider","endpoint":"endpoint"},"upstream":{"tier":"tee-verified","policy":"chutes-tdx-nvidia-e2e-v1","verified_at":1756223940,"verification_expires_at":1756224240},"att_sha256":"attestation"}`
	if string(encoded) != want {
		t.Fatalf("claims JSON = %s\nwant        = %s", encoded, want)
	}
}

func TestKidDerivation(t *testing.T) {
	signer := signerWithPublicKey(bytesFromZeroTo31())
	const want = "Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLIq8G4WBvXEN0"
	if got := signer.Kid(); got != want {
		t.Fatalf("Kid = %q, want %q", got, want)
	}
}

func TestKeyCommitmentUsesExactDomainSeparatedPreimage(t *testing.T) {
	signer := signerWithPublicKey(bytesFromZeroTo31())
	const wantHex = "3358a1e1737773945f5429970b3fb3c107ce660aa1ae3e676488138d51a354f7"
	commitment := signer.KeyCommitment()
	if got := hex.EncodeToString(commitment[:]); got != wantHex {
		t.Fatalf("KeyCommitment = %s, want golden %s", got, wantHex)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	compact, err := signer.SignCompact(testClaims())
	if err != nil {
		t.Fatalf("SignCompact: %v", err)
	}
	parts := strings.Split(compact, ".")
	payload, err := rawBase64.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	payload[len(payload)-2] ^= 1
	parts[1] = rawBase64.EncodeToString(payload)
	if err := Verify([]byte(strings.Join(parts, "."))); err == nil {
		t.Fatal("Verify accepted a tampered payload")
	}
}

func TestSignFlattenedCarriesAttestationOnlyInProtectedHeader(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	flattened, err := signer.SignFlattened(testClaims(), []byte("header.payload.signature"), "gcp-cs-jwt")
	if err != nil {
		t.Fatalf("SignFlattened: %v", err)
	}
	if err := Verify(flattened); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(flattened, &envelope); err != nil {
		t.Fatalf("unmarshal flattened JWS: %v", err)
	}
	if len(envelope) != 3 {
		t.Fatalf("flattened fields = %v, want protected/payload/signature only", envelope)
	}
	var protectedEncoded string
	if err := json.Unmarshal(envelope["protected"], &protectedEncoded); err != nil {
		t.Fatalf("unmarshal protected encoding: %v", err)
	}
	protectedJSON, err := rawBase64.DecodeString(protectedEncoded)
	if err != nil {
		t.Fatalf("decode protected header: %v", err)
	}
	var protected protectedHeader
	if err := json.Unmarshal(protectedJSON, &protected); err != nil {
		t.Fatalf("unmarshal protected header: %v", err)
	}
	if protected.Attestation != "header.payload.signature" {
		t.Fatalf("att = %q", protected.Attestation)
	}
	if protected.AttestationKind != "gcp-cs-jwt" {
		t.Fatalf("att_kind = %q", protected.AttestationKind)
	}
}

func TestSignFlattenedEncodesNitroDocumentAsBase64URL(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	attDoc := []byte{0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26}
	flattened, err := signer.SignFlattened(testClaims(), attDoc, "aws-nitro-cose")
	if err != nil {
		t.Fatalf("SignFlattened: %v", err)
	}
	var envelope flattenedJWS
	if err := json.Unmarshal(flattened, &envelope); err != nil {
		t.Fatalf("unmarshal flattened JWS: %v", err)
	}
	protectedJSON, err := rawBase64.DecodeString(envelope.Protected)
	if err != nil {
		t.Fatalf("decode protected header: %v", err)
	}
	var protected protectedHeader
	if err := json.Unmarshal(protectedJSON, &protected); err != nil {
		t.Fatalf("unmarshal protected header: %v", err)
	}
	if protected.Attestation != rawBase64.EncodeToString(attDoc) {
		t.Fatalf("att = %q, want base64url COSE", protected.Attestation)
	}
}

func signerWithPublicKey(publicKey []byte) *Signer {
	return &Signer{publicKey: ed25519.PublicKey(append([]byte(nil), publicKey...))}
}

func bytesFromZeroTo31() []byte {
	result := make([]byte, ed25519.PublicKeySize)
	for i := range result {
		result[i] = byte(i)
	}
	return result
}

func testClaims() Claims {
	events := 0
	return Claims{
		RV:         1,
		Issuer:     "https://api.trustedrouter.com",
		IssuedAt:   1_756_223_999,
		JTI:        "chatcmpl-test",
		Generation: "gen-test",
		Nonce:      "nonce_test",
		Route:      "chat.completions",
		Request:    HashRecord{Algorithm: "sha256", Hash: "request", Of: "body"},
		Response:   ResponseRecord{Algorithm: "sha256", Hash: "response", Of: "sse-data-v1", Events: &events},
		Model:      Model{Requested: "requested", Selected: "selected", Provider: "provider", Endpoint: "endpoint"},
		Upstream: Upstream{
			Tier:                  "tee-verified",
			Policy:                "chutes-tdx-nvidia-e2e-v1",
			VerifiedAt:            1_756_223_940,
			VerificationExpiresAt: 1_756_224_240,
		},
		AttSHA256: "attestation",
	}
}
