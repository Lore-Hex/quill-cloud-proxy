// External Account Binding — what a second ACME CA needs before it will talk
// to us at all.
//
// WHY THIS EXISTS. A Let's Encrypt outage is currently a total TLS outage on
// every enclave that uses ACME. The stated fix has been "point
// QUILL_ACME_DIRECTORY_URL at another CA", and that turns out to be only half
// true: the CAs worth failing over to — Google Trust Services, ZeroSSL,
// commercial ACME — all require External Account Binding, and this codebase
// registered accounts without it. Setting the directory URL alone fails at
// account registration with an error that names neither EAB nor the CA's
// docs, during an outage, which is the worst possible moment to discover that
// the fallback was never wired.
//
// EAB is how a CA links an ACME account to a paid/registered account it
// already knows about: the CA hands out a key ID and an HMAC key, and the
// client signs its account key with that HMAC to prove the link. RFC 8555 §7.3.4.
//
// The HMAC key is base64url, unpadded, in every CA's console. That encoding is
// not a detail we get to choose — decoding it as standard base64 or as hex
// yields a key that is the wrong bytes but the right shape, so registration
// fails with a signature error rather than a decoding one.
package enclavetls

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/acme"
)

// ExternalAccountBindingFromEnv builds the EAB from a key ID and a base64url
// HMAC key, or returns nil when neither is set.
//
// Partial configuration is an ERROR, never a silent fallback to no-EAB.
// Falling back would register a fresh unbound account against a CA that
// requires binding, and the resulting failure names the ACME protocol rather
// than the missing variable an operator can actually fix.
func ExternalAccountBindingFromEnv(kid, hmacKey string) (*acme.ExternalAccountBinding, error) {
	kid = strings.TrimSpace(kid)
	hmacKey = strings.TrimSpace(hmacKey)

	switch {
	case kid == "" && hmacKey == "":
		return nil, nil
	case kid == "":
		return nil, fmt.Errorf(
			"enclavetls: ACME EAB HMAC key is set but the key ID is not; " +
				"both come from the CA's console and neither works alone")
	case hmacKey == "":
		return nil, fmt.Errorf(
			"enclavetls: ACME EAB key ID is set but the HMAC key is not; " +
				"both come from the CA's console and neither works alone")
	}

	// base64url, unpadded — what every CA console emits. Tolerate padding
	// because operators paste it either way, but do NOT fall back to standard
	// base64: '-'/'_' and '+'/'/' decode to different bytes, so the wrong
	// alphabet yields a plausible-length key that fails as a SIGNATURE error
	// at registration, pointing nowhere near the real mistake.
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(hmacKey, "="))
	if err != nil {
		return nil, fmt.Errorf(
			"enclavetls: ACME EAB HMAC key must be base64url (the encoding the CA "+
				"console shows); decoding failed: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("enclavetls: ACME EAB HMAC key decoded to zero bytes")
	}

	return &acme.ExternalAccountBinding{KID: kid, Key: key}, nil
}
