package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestVerifyCompactJWSAuthenticatedKeyID(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	public := private.Public().(ed25519.PublicKey)
	for _, kid := range []string{"first", "second"} {
		t.Run(kid, func(t *testing.T) {
			payload := []byte(`{"iss":"issuer"}`)
			input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"`+kid+`","typ":"tr-async-settle-v1"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
			token := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))
			keys := map[string]ed25519.PublicKey{"first": public, "second": public}
			raw, got, err := VerifyCompactJWSWithKey(token, keys, "tr-async-settle-v1")
			if err != nil || got != kid || !bytes.Equal(raw, payload) {
				t.Fatalf("key=%q payload=%s error=%v", got, raw, err)
			}
			old, err := VerifyCompactJWS(token, keys, "tr-async-settle-v1")
			if err != nil || !bytes.Equal(old, payload) {
				t.Fatal("payload-only API changed")
			}
			for _, invalid := range []string{strings.Split(token, ".")[0] + "." + strings.Split(token, ".")[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)), "a.b.c"} {
				raw, got, err = VerifyCompactJWSWithKey(invalid, keys, "tr-async-settle-v1")
				if err == nil || raw != nil || got != "" {
					t.Fatal("unauthenticated key ID returned")
				}
			}
			delete(keys, kid)
			raw, got, err = VerifyCompactJWSWithKey(token, keys, "tr-async-settle-v1")
			if err == nil || raw != nil || got != "" {
				t.Fatal("unconfigured kid accepted via identical key")
			}
		})
	}
}
