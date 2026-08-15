package byokcache

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// The v2 associated data must stay byte-identical to _aad_v2 in quill-router's
// byok_crypto.py. A divergence is not a test failure in the usual sense — it is
// every BYOK key written by one side failing to open on the other.
//
// This vector was produced by the Python implementation and pasted here. If it
// ever fails, one of the two encoders changed and the migration is broken.
// Not a credential; a fixed plaintext so the round trip asserts something.
const testProviderSecret = "opaque-test-plaintext" //nolint:gosec // fixture, not a credential

const pythonVectorProviderWs1OpenAI = "0000001574727573746564726f757465722f62796f6b2f76320000000870726f76696465720000000477732d31000000066f70656e6169"

func TestAADv2MatchesTheControlPlaneVector(t *testing.T) {
	got := hex.EncodeToString(mustAADv2(t, "provider", "ws-1", "openai"))
	if got != pythonVectorProviderWs1OpenAI {
		t.Fatalf("v2 AAD diverged from the control plane\n got: %s\nwant: %s", got, pythonVectorProviderWs1OpenAI)
	}
}

// The property v1 lacks: the encoding is injective, so no two distinct tuples
// produce the same associated data.
func TestAADv2IsInjective(t *testing.T) {
	alphabet := []string{"", "a", ":", "a:", ":a", "aa", "\x00", "trustedrouter", "/", "b"}
	seen := map[string][3]string{}
	for _, ns := range []string{"provider", "control"} {
		for _, w := range alphabet {
			for _, c := range alphabet {
				key := string(mustAADv2(t, ns, w, c))
				tuple := [3]string{ns, w, c}
				if prev, ok := seen[key]; ok && prev != tuple {
					t.Fatalf("collision: %v and %v produce identical AAD", prev, tuple)
				}
				seen[key] = tuple
			}
		}
	}
	if len(seen) != 2*len(alphabet)*len(alphabet) {
		t.Fatalf("expected %d distinct AADs, got %d", 2*len(alphabet)*len(alphabet), len(seen))
	}
}

// The v1 collisions, pinned so the contrast is explicit and so nobody
// "simplifies" v2 back toward a delimiter-joined form.
func TestAADv1IsNotInjective(t *testing.T) {
	if string(aad("a:b", "c")) != string(aad("a", "b:c")) {
		t.Fatal("expected the documented v1 collision; if this fails, v1 changed")
	}
	if string(mustAADv2(t, "provider", "a:b", "c")) == string(mustAADv2(t, "provider", "a", "b:c")) {
		t.Fatal("v2 inherited the v1 collision")
	}
}

// A namespace separates the secret families even when the context strings match
// exactly. The enclave only ever passes "provider", but the encoding has to
// carry the distinction or the control plane's separation is not real.
func TestAADv2SeparatesNamespaces(t *testing.T) {
	if string(mustAADv2(t, "provider", "w", "x")) == string(mustAADv2(t, "control", "w", "x")) {
		t.Fatal("provider and control namespaces collide")
	}
}

func TestEnvelopeAADSelectsByAlgorithm(t *testing.T) {
	v1, err := envelopeAAD(Algorithm, "w", "p")
	if err != nil {
		t.Fatalf("v1: %v", err)
	}
	if string(v1) != string(aad("w", "p")) {
		t.Fatal("v1 envelopes must use the v1 AAD")
	}

	v2, err := envelopeAAD(AlgorithmV2, "w", "p")
	if err != nil {
		t.Fatalf("v2: %v", err)
	}
	if string(v2) != string(mustAADv2(t, namespaceProvider, "w", "p")) {
		t.Fatal("v2 envelopes must use the v2 AAD with the provider namespace")
	}

	// An unknown algorithm must still be refused rather than defaulted.
	if _, err := envelopeAAD("TR-BYOK-ENVELOPE-AES-256-GCM-V3", "w", "p"); err == nil {
		t.Fatal("an unrecognised algorithm must be rejected, not defaulted to a format")
	}
}

// End to end: a v2 envelope sealed exactly as the control plane will seal it
// must open, and v1 envelopes must keep opening. This is the property that
// makes step 2 of the migration safe to ship.
func TestResolveOpensBothEnvelopeFormats(t *testing.T) {
	for _, tc := range []struct {
		name      string
		algorithm string
		aad       []byte
	}{
		{"v1 keeps working", Algorithm, aad("ws-1", "openai")},
		{"v2 opens", AlgorithmV2, mustAADv2(t, namespaceProvider, "ws-1", "openai")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envelope := sealWith(t, tc.algorithm, tc.aad, testProviderSecret)
			cache := New(Options{Unwrapper: &fakeUnwrapper{dek: fixedDEK()}})

			secret, _, err := cache.Resolve(
				context.Background(), "ws-1", "openai", "cache-key", envelope)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if secret != testProviderSecret {
				t.Fatalf("got %q", secret)
			}
		})
	}
}

// A v2 envelope must not open under the v1 AAD, or the migration would be
// cosmetic — both formats would be interchangeable and the collision would
// survive.
func TestV2EnvelopeDoesNotOpenUnderV1AAD(t *testing.T) {
	envelope := sealWith(t, AlgorithmV2, aad("ws-1", "openai"), testProviderSecret)
	cache := New(Options{Unwrapper: &fakeUnwrapper{dek: fixedDEK()}})

	if _, _, err := cache.Resolve(
		context.Background(), "ws-1", "openai", "k", envelope); err == nil {
		t.Fatal("a v2 envelope sealed under v1 AAD must fail to open")
	}
}

func sealWith(t *testing.T, algorithm string, associated []byte, secret string) EncryptedSecretEnvelope {
	t.Helper()
	block, err := aes.NewCipher(fixedDEK())
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("123456789012")
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), associated)
	return EncryptedSecretEnvelope{
		Algorithm:    algorithm,
		KeyRef:       "projects/p/locations/l/keyRings/r/cryptoKeys/k",
		EncryptedDEK: base64.URLEncoding.EncodeToString([]byte("wrapped-dek")),
		DEKNonce:     base64.URLEncoding.EncodeToString(nonce),
		Ciphertext:   base64.URLEncoding.EncodeToString(ciphertext),
		Nonce:        base64.URLEncoding.EncodeToString(nonce),
	}
}

func mustAADv2(t *testing.T, namespace, workspaceID, context string) []byte {
	t.Helper()
	out, err := aadV2(namespace, workspaceID, context)
	if err != nil {
		t.Fatalf("aadV2(%q,%q,%q): %v", namespace, workspaceID, context, err)
	}
	return out
}
