package enclavetls

import (
	"encoding/base64"
	"strings"
	"testing"
)

// A key whose base64url and standard-base64 encodings DIFFER, which is the
// whole point: bytes containing 0xFB/0xFF produce '-'/'_' in base64url and
// '+'/'/' in standard base64. A test using a key that encodes identically in
// both would pass against a decoder using the wrong alphabet.
var eabKey = []byte{0xFB, 0xEF, 0xBE, 0x00, 0x11, 0x22, 0xFF, 0xFE}

func TestUnsetYieldsNoBinding(t *testing.T) {
	// Let's Encrypt does not use EAB. The default path must stay untouched.
	eab, err := ExternalAccountBindingFromEnv("", "")
	if err != nil {
		t.Fatalf("unset should not error: %v", err)
	}
	if eab != nil {
		t.Fatalf("unset should yield nil, got %+v", eab)
	}
}

func TestPartialConfigurationIsFatal(t *testing.T) {
	// The dangerous alternative is falling back to no-EAB: the enclave then
	// registers a fresh UNBOUND account against a CA that requires binding,
	// and the failure names the ACME protocol instead of the missing variable.
	for _, tc := range []struct{ name, kid, key string }{
		{"key without kid", "", base64.RawURLEncoding.EncodeToString(eabKey)},
		{"kid without key", "some-kid", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eab, err := ExternalAccountBindingFromEnv(tc.kid, tc.key)
			if err == nil {
				t.Fatalf("partial config accepted, got %+v", eab)
			}
			if !strings.Contains(err.Error(), "neither works alone") {
				t.Errorf("error should tell the operator both are needed: %v", err)
			}
		})
	}
}

func TestHMACKeyIsDecodedAsBase64URL(t *testing.T) {
	// THE encoding trap. Every CA console shows base64url, unpadded. Decoding
	// it as standard base64 yields a key of plausible LENGTH but wrong BYTES,
	// so registration fails with a signature error that points nowhere near
	// the real mistake.
	eab, err := ExternalAccountBindingFromEnv("kid-1", base64.RawURLEncoding.EncodeToString(eabKey))
	if err != nil {
		t.Fatalf("valid base64url rejected: %v", err)
	}
	if eab.KID != "kid-1" {
		t.Errorf("KID = %q, want kid-1", eab.KID)
	}
	if string(eab.Key) != string(eabKey) {
		t.Fatalf("Key = %x, want %x — wrong base64 alphabet", eab.Key, eabKey)
	}
}

func TestPaddingIsTolerated(t *testing.T) {
	// Operators paste from consoles that pad and consoles that do not. Both
	// must work; rejecting padding would be a 2am failure over a '='.
	padded := base64.URLEncoding.EncodeToString(eabKey)
	if !strings.HasSuffix(padded, "=") {
		t.Fatalf("test needs a padded fixture, got %q", padded)
	}
	eab, err := ExternalAccountBindingFromEnv("kid-1", padded)
	if err != nil {
		t.Fatalf("padded base64url rejected: %v", err)
	}
	if string(eab.Key) != string(eabKey) {
		t.Fatalf("Key = %x, want %x", eab.Key, eabKey)
	}
}

func TestWhitespaceIsTrimmed(t *testing.T) {
	// Copy-paste out of a console or a YAML block routinely carries these.
	eab, err := ExternalAccountBindingFromEnv(
		"  kid-1\n", "\t"+base64.RawURLEncoding.EncodeToString(eabKey)+"  ")
	if err != nil {
		t.Fatalf("whitespace rejected: %v", err)
	}
	if eab.KID != "kid-1" || string(eab.Key) != string(eabKey) {
		t.Fatalf("got KID=%q key=%x", eab.KID, eab.Key)
	}
}

func TestUndecodableKeyIsFatalAndNamesTheEncoding(t *testing.T) {
	_, err := ExternalAccountBindingFromEnv("kid-1", "not valid base64 !!!")
	if err == nil {
		t.Fatal("garbage key accepted")
	}
	if !strings.Contains(err.Error(), "base64url") {
		t.Errorf("error should name the expected encoding: %v", err)
	}
}

func TestEmptyDecodedKeyIsFatal(t *testing.T) {
	// "=" decodes to zero bytes without erroring. A zero-length HMAC key
	// would sign nothing and fail remotely rather than here.
	if _, err := ExternalAccountBindingFromEnv("kid-1", "="); err == nil {
		t.Fatal("zero-byte key accepted")
	}
}
