package spendlease

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type testIssuer struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	kid     string
}

func newTestIssuer(t *testing.T, now time.Time) (testIssuer, *Verifier) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(publicKey)
	kid := base64.RawURLEncoding.EncodeToString(digest[:])
	config, err := json.Marshal(IssuerConfig{Version: 1, Keys: []IssuerKey{{
		KID: kid, JWK: JWK{KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(publicKey)},
		NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	return testIssuer{publicKey, privateKey, kid}, verifier
}

func validTestClaims(now time.Time) Claims {
	return Claims{
		Version: 1, Type: JWSType, LeaseID: "123e4567-e89b-42d3-a456-426614174000",
		KeyHash: "key-1", WorkspaceID: "ws-1", Cohort: Cohort,
		CapMicro: 100, Generation: 1, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		BootKID: "boot-1", Catalog: Catalog{Version: "catalog-1", Candidates: []Candidate{{
			EndpointID: "endpoint-1", Model: "model-1", Provider: "provider-1",
			Region: "us-central1", RouteType: "chat.completions", RequestPriceMicro: 1,
		}}},
	}
}

func signTestLease(t *testing.T, issuer testIssuer, claims Claims, typ, kid string, embedded JWK) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "EdDSA", "typ": typ, "kid": kid, "jwk": embedded})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	protected := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := protected + "." + encodedPayload
	signature := ed25519.Sign(issuer.private, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerifierAcceptRejectMatrix(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	issuer, verifier := newTestIssuer(t, now)
	embedded := JWK{KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(issuer.public)}
	valid := validTestClaims(now)

	t.Run("accept valid and arm deadline from receipt", func(t *testing.T) {
		lease, err := verifier.VerifyShadowAt(signTestLease(t, issuer, valid, JWSType, issuer.kid, embedded), now)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := lease.Deadline.Sub(now), MaximumTTL+Skew; got != want {
			t.Fatalf("deadline = %v after receipt, want %v", got, want)
		}
		if got, want := lease.AdmitUntil.Sub(now), MaximumTTL-AdmissionMargin; got != want {
			t.Fatalf("admit-until = %v after receipt, want %v", got, want)
		}
	})

	t.Run("expired", func(t *testing.T) {
		_, err := verifier.VerifyShadowAt(signTestLease(t, issuer, valid, JWSType, issuer.kid, embedded), time.Unix(valid.ExpiresAt+11, 0))
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("err = %v, want expired", err)
		}
	})

	t.Run("ten second skew edge accepted", func(t *testing.T) {
		if _, err := verifier.VerifyShadowAt(signTestLease(t, issuer, valid, JWSType, issuer.kid, embedded), time.Unix(valid.ExpiresAt+10, 0)); err != nil {
			t.Fatalf("skew edge rejected: %v", err)
		}
	})

	t.Run("wrong typ", func(t *testing.T) {
		if _, err := verifier.VerifyShadowAt(signTestLease(t, issuer, valid, "JWT", issuer.kid, embedded), now); err == nil {
			t.Fatal("wrong typ accepted")
		}
	})

	t.Run("wrong alg", func(t *testing.T) {
		token := signTestLease(t, issuer, valid, JWSType, issuer.kid, embedded)
		parts := strings.Split(token, ".")
		var header map[string]any
		headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
		_ = json.Unmarshal(headerJSON, &header)
		header["alg"] = "Ed25519"
		headerJSON, _ = json.Marshal(header)
		parts[0] = base64.RawURLEncoding.EncodeToString(headerJSON)
		parts[2] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuer.private, []byte(parts[0]+"."+parts[1])))
		if _, err := verifier.VerifyShadowAt(strings.Join(parts, "."), now); err == nil {
			t.Fatal("wrong alg accepted")
		}
	})

	t.Run("iat outside issuer validity window", func(t *testing.T) {
		outside := valid
		outside.IssuedAt = now.Add(2 * time.Hour).Unix()
		outside.ExpiresAt = now.Add(2*time.Hour + time.Minute).Unix()
		if _, err := verifier.VerifyShadowAt(signTestLease(t, issuer, outside, JWSType, issuer.kid, embedded), now.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "validity window") {
			t.Fatalf("issuer validity window not enforced: %v", err)
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		token := signTestLease(t, issuer, valid, JWSType, issuer.kid, embedded)
		parts := strings.Split(token, ".")
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		payload[len(payload)-2] ^= 1
		parts[1] = base64.RawURLEncoding.EncodeToString(payload)
		if _, err := verifier.VerifyShadowAt(strings.Join(parts, "."), now); err == nil {
			t.Fatal("tampered payload accepted")
		}
	})

	t.Run("authoritative refused as Stage A authority", func(t *testing.T) {
		authoritative := valid
		authoritative.Authoritative = true
		token := signTestLease(t, issuer, authoritative, JWSType, issuer.kid, embedded)
		if _, err := verifier.VerifyAt(token, now); err != nil {
			t.Fatalf("cryptographic verification failed: %v", err)
		}
		if _, err := verifier.VerifyShadowAt(token, now); err == nil || !strings.Contains(err.Error(), "Stage A") {
			t.Fatalf("authoritative shadow grant was not refused: %v", err)
		}
	})
}

// Mutation target (a): deleting the configured-kid lookup makes this test
// fail by accepting an attacker key carried only in the protected header.
func TestVerifierRejectsUnconfiguredKIDEvenWithValidEmbeddedJWK(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	_, verifier := newTestIssuer(t, now)
	attacker, _ := newTestIssuer(t, now)
	embedded := JWK{KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(attacker.public)}
	token := signTestLease(t, attacker, validTestClaims(now), JWSType, attacker.kid, embedded)
	if _, err := verifier.VerifyShadowAt(token, now); err == nil || !strings.Contains(err.Error(), "unconfigured issuer kid") {
		t.Fatalf("unconfigured embedded key accepted: %v", err)
	}
}

func TestVerifierRejectsKIDThatDoesNotNameSigningConfiguredKey(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	first, _ := newTestIssuer(t, now)
	second, _ := newTestIssuer(t, now)
	config, _ := json.Marshal(IssuerConfig{Version: 1, Keys: []IssuerKey{
		{KID: first.kid, JWK: JWK{KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(first.public)}, NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix()},
		{KID: second.kid, JWK: JWK{KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(second.public)}, NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix()},
	}})
	verifier, err := NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	embedded := JWK{KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(second.public)}
	// The signature is by configured key two, but the protected kid names
	// configured key one. Trying every configured key instead of enforcing kid
	// would accept it.
	token := signTestLease(t, second, validTestClaims(now), JWSType, first.kid, embedded)
	if _, err := verifier.VerifyShadowAt(token, now); err == nil {
		t.Fatal("signature by a different configured key accepted under the claimed kid")
	}
}
