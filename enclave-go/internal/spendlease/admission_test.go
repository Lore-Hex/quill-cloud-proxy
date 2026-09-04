package spendlease

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/receipt"
)

func TestAdmissionReceiptUsesExactProtectedHeaderAndEd25519Message(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	signer, err := receipt.NewSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	claims := AdmissionReceiptClaims{
		Version: 1, LeaseID: "123e4567-e89b-42d3-a456-426614174000", Generation: 7,
		KeyHash: "key", WorkspaceID: "workspace", BootKID: signer.Kid(),
		IdempotencyKeySHA256: strings.Repeat("1", 64), RoutingPolicyHash: strings.Repeat("2", 64),
		EnclaveEstimateMicro: 41, RemainingAfterMicro: 59, AdmittedAtMS: 2_000_000_000_123,
	}
	token, err := SignAdmissionReceipt(signer, claims)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := receipt.ParseJWS([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := fmt.Sprintf(`{"alg":"EdDSA","kid":%q,"typ":"spend_lease_admission+jws"}`, signer.Kid())
	if string(parts.ProtectedJSON) != wantHeader || strings.Contains(string(parts.ProtectedJSON), `"jwk"`) {
		t.Fatalf("protected header = %s, want %s without jwk", parts.ProtectedJSON, wantHeader)
	}
	wantPayload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	if string(parts.PayloadJSON) != string(wantPayload) {
		t.Fatalf("payload = %s, want %s", parts.PayloadJSON, wantPayload)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(signer.JWK().X)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, parts.SigningInput, parts.Signature) {
		t.Fatal("receipt is not an Ed25519 signature over the compact-JWS signing input")
	}
}
