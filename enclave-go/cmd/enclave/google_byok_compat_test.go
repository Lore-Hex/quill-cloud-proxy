package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
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

func TestLegacyGeminiEnvelopeDecryptsForAIStudioRoute(t *testing.T) {
	const (
		workspaceID = "workspace-google-compat"
		legacySlug  = "gemini"
		secret      = "AIza-legacy-google-key"
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
	authorization.BYOKCacheKey = "force-another-decrypt"
	_, err = invokeOptionsForAuthorization(t.Context(), cache, authorization)
	if err == nil || !strings.Contains(err.Error(), "message authentication failed") {
		t.Fatalf("missing legacy AAD unexpectedly succeeded: %v", err)
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
	aad := []byte("trustedrouter:byok:" + workspaceID + ":" + provider)
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), aad)
	return byokcache.EncryptedSecretEnvelope{
		Algorithm:    byokcache.Algorithm,
		KeyRef:       "projects/test/locations/global/keyRings/tr/cryptoKeys/byok",
		EncryptedDEK: base64.URLEncoding.EncodeToString([]byte("wrapped-dek")),
		DEKNonce:     base64.URLEncoding.EncodeToString([]byte("dek-nonce")),
		Ciphertext:   base64.URLEncoding.EncodeToString(ciphertext),
		Nonce:        base64.URLEncoding.EncodeToString(nonce),
	}
}
