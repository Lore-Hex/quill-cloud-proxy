package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

type googleCompatUnwrapper struct {
	dek []byte
}

func (u *googleCompatUnwrapper) UnwrapDEK(
	_ context.Context,
	_ string,
	_ []byte,
	_ []byte,
) ([]byte, error) {
	return append([]byte(nil), u.dek...), nil
}

func TestLegacyGeminiProviderIdentityDecryptsForAIStudioRoute(t *testing.T) {
	const (
		workspaceID = "workspace-google-compat"
		legacySlug  = "gemini"
		secret      = "test-provider-secret-value"
	)
	dek := []byte("0123456789abcdef0123456789abcdef")
	envelope := googleCompatEnvelope(t, dek, workspaceID, legacySlug, secret)
	cache := byokcache.New(byokcache.Options{
		Unwrapper: &googleCompatUnwrapper{dek: dek},
	})
	authorization := &trustedrouter.Authorization{
		WorkspaceID:         workspaceID,
		Model:               "google/gemini-2.5-flash",
		UpstreamModel:       "gemini-2.5-flash",
		EndpointID:          "google/gemini-2.5-flash@google-ai-studio/byok",
		Provider:            "google-ai-studio",
		UsageType:           "BYOK",
		BYOKProvider:        legacySlug,
		BYOKEncryptedSecret: &envelope,
	}

	options, err := invokeOptionsForAuthorization(t.Context(), cache, authorization)
	if err != nil {
		t.Fatalf("invokeOptionsForAuthorization: %v", err)
	}
	if len(options) != 1 {
		t.Fatalf("options = %d, want 1", len(options))
	}
	if got := options[0].Provider; got != "google-ai-studio" {
		t.Fatalf("dispatch provider = %q", got)
	}
	if got := options[0].ProviderAPIKey; got != secret {
		t.Fatalf("provider key = %q", got)
	}

	// The compatibility field is security-relevant: the provider slug is AAD.
	// Without it, the renamed route must not accidentally decrypt an envelope
	// created under the old storage identity.
	authorization.BYOKProvider = ""
	authorization.BYOKCacheKey = byokcache.Fingerprint(
		workspaceID, authorization.Provider, envelope,
	)
	_, err = invokeOptionsForAuthorization(t.Context(), cache, authorization)
	if err == nil || !strings.Contains(err.Error(), "message authentication failed") {
		t.Fatalf("missing legacy AAD unexpectedly succeeded: %v", err)
	}
}

func TestRetiredBYOKEnvelopeDoesNotFallThroughToCredits(t *testing.T) {
	envelope := byokcache.EncryptedSecretEnvelope{
		Algorithm: "TR-BYOK-ENVELOPE-AES-256-GCM-V1",
	}
	authorization := &trustedrouter.Authorization{
		WorkspaceID: "workspace-retired-envelope",
		Model:       "openai/gpt-5.5",
		RouteCandidates: []trustedrouter.RouteCandidate{
			{
				EndpointID:          "openai/gpt-5.5@openai/byok",
				Model:               "openai/gpt-5.5",
				Provider:            "openai",
				UsageType:           "BYOK",
				BYOKEncryptedSecret: &envelope,
			},
			{
				EndpointID: "openai/gpt-5.5@openai/credits",
				Model:      "openai/gpt-5.5",
				Provider:   "openai",
				UsageType:  "Credits",
			},
		},
	}

	options, err := invokeOptionsForAuthorization(t.Context(), nil, authorization)
	if err == nil || !strings.Contains(err.Error(), "unsupported encrypted secret envelope") {
		t.Fatalf("retired BYOK envelope result = (%#v, %v), want fail-closed error", options, err)
	}
}

func googleCompatEnvelope(
	t *testing.T,
	dek []byte,
	workspaceID string,
	provider string,
	secret string,
) byokcache.EncryptedSecretEnvelope {
	t.Helper()
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("123456789012")
	aad := googleCompatAADV2("provider", workspaceID, provider)
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), aad)
	return byokcache.EncryptedSecretEnvelope{
		Algorithm:    byokcache.AlgorithmV2,
		KeyRef:       "projects/test/locations/global/keyRings/tr/cryptoKeys/byok",
		EncryptedDEK: base64.URLEncoding.EncodeToString([]byte("wrapped-dek")),
		DEKNonce:     base64.URLEncoding.EncodeToString([]byte("dek-nonce")),
		Ciphertext:   base64.URLEncoding.EncodeToString(ciphertext),
		Nonce:        base64.URLEncoding.EncodeToString(nonce),
	}
}

func googleCompatAADV2(parts ...string) []byte {
	parts = append([]string{"trustedrouter/byok/v2"}, parts...)
	var out []byte
	var length [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(length[:], uint32(len(part))) //nolint:gosec // fixed test data
		out = append(out, length[:]...)
		out = append(out, part...)
	}
	return out
}
