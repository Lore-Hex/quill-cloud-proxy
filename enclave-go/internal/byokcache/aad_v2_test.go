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

const retiredV1Algorithm = "TR-BYOK-ENVELOPE-AES-256-GCM-V1"

const pythonVectorProviderWs1OpenAI = "0000001574727573746564726f757465722f62796f6b2f76320000000870726f76696465720000000477732d31000000066f70656e6169"

const pythonVectorUserModelWs1Signing = "0000001574727573746564726f757465722f62796f6b2f76320000000a757365725f6d6f64656c0000000477732d3100000012757365725f6d6f64656c5f7369676e696e67"

func TestAADv2MatchesTheControlPlaneVector(t *testing.T) {
	got := hex.EncodeToString(mustAADv2(t, "provider", "ws-1", "openai"))
	if got != pythonVectorProviderWs1OpenAI {
		t.Fatalf("v2 AAD diverged from the control plane\n got: %s\nwant: %s", got, pythonVectorProviderWs1OpenAI)
	}
}

func TestUserModelAADv2MatchesTheControlPlaneVector(t *testing.T) {
	got := hex.EncodeToString(mustAADv2(t, namespaceUserModel, "ws-1", "user_model_signing"))
	if got != pythonVectorUserModelWs1Signing {
		t.Fatalf("user-model v2 AAD diverged from the control plane\n got: %s\nwant: %s", got, pythonVectorUserModelWs1Signing)
	}
}

// The property v1 lacks: the encoding is injective, so no two distinct tuples
// produce the same associated data.
func TestAADv2IsInjective(t *testing.T) {
	alphabet := []string{"", "a", ":", "a:", ":a", "aa", "\x00", "trustedrouter", "/", "b"}
	seen := map[string][3]string{}
	for _, ns := range []string{"provider", "control", "user_model"} {
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
	if len(seen) != 3*len(alphabet)*len(alphabet) {
		t.Fatalf("expected %d distinct AADs, got %d", 3*len(alphabet)*len(alphabet), len(seen))
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
	if _, err := envelopeAAD(retiredV1Algorithm, namespaceProvider, "w", "p"); err == nil {
		t.Fatal("a retired v1 envelope must be rejected")
	}

	v2, err := envelopeAAD(AlgorithmV2, namespaceProvider, "w", "p")
	if err != nil {
		t.Fatalf("v2: %v", err)
	}
	if string(v2) != string(mustAADv2(t, namespaceProvider, "w", "p")) {
		t.Fatal("v2 envelopes must use the v2 AAD with the provider namespace")
	}

	// Control secrets are intentionally decrypted only by the control plane.
	// Even a current-format control envelope must never become enclave input.
	if _, err := envelopeAAD(AlgorithmV2, "control", "w", "p"); err == nil {
		t.Fatal("a control-secret envelope must be rejected by the enclave")
	}

	// An unknown algorithm must still be refused rather than defaulted.
	if _, err := envelopeAAD("TR-BYOK-ENVELOPE-AES-256-GCM-V3", namespaceProvider, "w", "p"); err == nil {
		t.Fatal("an unrecognised algorithm must be rejected, not defaulted to a format")
	}
}

func TestResolveUserModelIsV2OnlyAndNamespaceBound(t *testing.T) {
	associated := mustAADv2(t, namespaceUserModel, "owner-ws", "user_model_signing")
	envelope := sealWith(t, AlgorithmV2, associated, testProviderSecret)
	cache := New(Options{Unwrapper: &fakeUnwrapper{dek: fixedDEK()}})

	secret, cached, err := cache.ResolveUserModel(
		context.Background(), "owner-ws", "user_model_signing", envelope,
	)
	if err != nil {
		t.Fatalf("ResolveUserModel: %v", err)
	}
	if cached || secret != testProviderSecret {
		t.Fatalf("first resolve = (%q, cached=%v)", secret, cached)
	}
	if _, cached, err := cache.ResolveUserModel(
		context.Background(), "owner-ws", "user_model_signing", envelope,
	); err != nil || !cached {
		t.Fatalf("second resolve = (cached=%v, err=%v)", cached, err)
	}

	relabeled := envelope
	relabeled.Algorithm = retiredV1Algorithm
	if _, _, err := cache.ResolveUserModel(
		context.Background(), "owner-ws", "user_model_signing", relabeled,
	); err == nil {
		t.Fatal("a cached V2 user-model envelope opened after being relabeled V1")
	}

	v1 := sealWith(t, retiredV1Algorithm, retiredV1AAD("owner-ws", "user_model_signing"), testProviderSecret)
	if _, _, err := cache.ResolveUserModel(
		context.Background(), "owner-ws", "user_model_signing", v1,
	); err == nil {
		t.Fatal("user-model v1 envelope unexpectedly opened")
	}
	providerAAD := sealWith(t, AlgorithmV2, mustAADv2(t, namespaceProvider, "owner-ws", "user_model_signing"), testProviderSecret)
	if _, _, err := cache.ResolveUserModel(
		context.Background(), "owner-ws", "user_model_signing", providerAAD,
	); err == nil {
		t.Fatal("provider-namespace envelope unexpectedly opened as a user-model secret")
	}
}

func TestUserModelRewrapCannotReuseCachedPlaintext(t *testing.T) {
	associated := mustAADv2(t, namespaceUserModel, "owner-ws", "user_model_signing")
	envelope := sealWith(t, AlgorithmV2, associated, testProviderSecret)
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{Unwrapper: unwrapper})

	if _, cached, err := cache.ResolveUserModel(
		context.Background(), "owner-ws", "user_model_signing", envelope,
	); err != nil || cached {
		t.Fatalf("prime user-model cache = (cached=%v, err=%v)", cached, err)
	}

	rewrapped := envelope
	rewrapped.KeyRef = envelope.KeyRef + "/rotated"
	rewrapped.EncryptedDEK = base64.URLEncoding.EncodeToString([]byte("rewrapped-dek"))
	if _, cached, err := cache.ResolveUserModel(
		context.Background(), "owner-ws", "user_model_signing", rewrapped,
	); err != nil || cached {
		t.Fatalf("rewrapped user-model resolve = (cached=%v, err=%v)", cached, err)
	}
	if unwrapper.calls != 2 {
		t.Fatalf("unwrapper calls = %d, want 2", unwrapper.calls)
	}
}

func TestUserModelCacheCannotAliasProviderCacheKey(t *testing.T) {
	providerEnvelope := sealWith(
		t, AlgorithmV2, mustAADv2(t, namespaceProvider, "owner-ws", "user_model_signing"), "provider-secret",
	)
	userEnvelope := sealWith(
		t, AlgorithmV2, mustAADv2(t, namespaceUserModel, "owner-ws", "user_model_signing"), "user-secret",
	)
	cache := New(Options{Unwrapper: &fakeUnwrapper{dek: fixedDEK()}})
	collidingKey, err := userModelFingerprint("owner-ws", "user_model_signing", userEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.Resolve(
		context.Background(), "owner-ws", "user_model_signing", collidingKey, providerEnvelope,
	); err == nil {
		t.Fatal("provider resolve accepted a user-model-derived cache key")
	}
	providerKey := Fingerprint("owner-ws", "user_model_signing", providerEnvelope)
	if secret, _, err := cache.Resolve(
		context.Background(), "owner-ws", "user_model_signing", providerKey, providerEnvelope,
	); err != nil || secret != "provider-secret" {
		t.Fatalf("prime provider cache = (%q, %v)", secret, err)
	}
	secret, cached, err := cache.ResolveUserModel(
		context.Background(), "owner-ws", "user_model_signing", userEnvelope,
	)
	if err != nil || cached || secret != "user-secret" {
		t.Fatalf("user-model resolve = (%q, cached=%v, err=%v)", secret, cached, err)
	}
}

// End to end: a v2 envelope sealed exactly as the control plane seals it opens.
func TestResolveOpensV2Envelope(t *testing.T) {
	envelope := sealWith(
		t, AlgorithmV2, mustAADv2(t, namespaceProvider, "ws-1", "openai"), testProviderSecret,
	)
	cache := New(Options{Unwrapper: &fakeUnwrapper{dek: fixedDEK()}})

	secret, _, err := cache.Resolve(
		context.Background(), "ws-1", "openai", "", envelope)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if secret != testProviderSecret {
		t.Fatalf("got %q", secret)
	}
}

func TestResolveRejectsRetiredV1EnvelopeBeforeUnwrap(t *testing.T) {
	envelope := sealWith(
		t,
		retiredV1Algorithm,
		retiredV1AAD("ws-1", "openai"),
		testProviderSecret,
	)
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{Unwrapper: unwrapper})

	if _, _, err := cache.Resolve(
		context.Background(), "ws-1", "openai", "", envelope,
	); err == nil {
		t.Fatal("a retired v1 envelope unexpectedly opened")
	}
	if unwrapper.calls != 0 {
		t.Fatalf("retired format reached the DEK unwrapper %d times", unwrapper.calls)
	}
}

func TestResolveRejectsRelabeledCachedProviderEnvelope(t *testing.T) {
	envelope := sealWith(
		t,
		AlgorithmV2,
		mustAADv2(t, namespaceProvider, "ws-1", "openai"),
		testProviderSecret,
	)
	unwrapper := &fakeUnwrapper{dek: fixedDEK()}
	cache := New(Options{Unwrapper: unwrapper})

	if _, cached, err := cache.Resolve(
		context.Background(), "ws-1", "openai", "", envelope,
	); err != nil || cached {
		t.Fatalf("prime provider cache = (cached=%v, err=%v)", cached, err)
	}
	relabeled := envelope
	relabeled.Algorithm = retiredV1Algorithm
	if _, _, err := cache.Resolve(
		context.Background(), "ws-1", "openai", "", relabeled,
	); err == nil {
		t.Fatal("a cached V2 provider envelope opened after being relabeled V1")
	}
	if unwrapper.calls != 1 {
		t.Fatalf("relabeled format reached the DEK unwrapper; calls = %d", unwrapper.calls)
	}
}

// A v2 envelope must not open under the v1 AAD, or the migration would be
// cosmetic — both formats would be interchangeable and the collision would
// survive.
func TestV2EnvelopeDoesNotOpenUnderV1AAD(t *testing.T) {
	envelope := sealWith(t, AlgorithmV2, retiredV1AAD("ws-1", "openai"), testProviderSecret)
	cache := New(Options{Unwrapper: &fakeUnwrapper{dek: fixedDEK()}})

	if _, _, err := cache.Resolve(
		context.Background(), "ws-1", "openai", "", envelope); err == nil {
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

func retiredV1AAD(workspaceID, context string) []byte {
	return []byte("trustedrouter:byok:" + workspaceID + ":" + context)
}
