// Package attestation talks to the Nitro Security Module via /dev/nsm.
//
// The NSM produces an attestation document — a CBOR-encoded, COSE-signed
// blob that commits to:
//   - the running enclave's PCR values (PCR0 is what the trust page
//     publishes; PCR1..PCR7 are kernel/initramfs/locked-state)
//   - an AWS-Nitro-issued certificate chain rooted in AWS's PKI
//   - optional public-key, user-data, and nonce fields that the caller
//     embeds at the time of the request
//
// We bind the document to our TLS leaf cert by setting:
//   - PublicKey = DER-encoded SubjectPublicKeyInfo of the leaf
//   - UserData  = SHA-256 of the leaf cert in DER form (redundant but
//                 lets clients use a cheap hash check)
//
// Result: a client can fetch the attestation doc, verify it against AWS's
// root, check PCR0 against the trust page, and check the cert presented in
// their live TLS handshake matches the document's PublicKey. All four of
// those bind together to "the bytes I'm sending are encrypted to a
// specific build of code I trust."
//
// Nitriding-style; same shape Brave's daemon uses.
package attestation

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

// Get returns a fresh attestation document binding the given leaf cert
// (and an optional client-supplied nonce) into the NSM-signed COSE blob.
//
// `nonce` may be nil; it's a freshness signal supplied by the caller so
// they know the document was generated for *their* request, not replayed.
func Get(leafDER []byte, nonce []byte) ([]byte, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("attestation: parse leaf: %w", err)
	}

	// SubjectPublicKeyInfo bytes — the same blob a client extracts from
	// the cert to compare against the attestation doc.
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("attestation: marshal public key: %w", err)
	}

	// SHA-256 of the cert (DER) — also embedded so a hash-only client
	// doesn't have to do ASN.1 parsing.
	fp := sha256.Sum256(leafDER)

	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("attestation: open NSM: %w", err)
	}
	defer sess.Close()

	resp, err := sess.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  fp[:],
		PublicKey: spki,
	})
	if err != nil {
		return nil, fmt.Errorf("attestation: send: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("attestation: NSM error: %s", resp.Error)
	}
	if resp.Attestation == nil || resp.Attestation.Document == nil {
		return nil, errors.New("attestation: empty document")
	}
	return resp.Attestation.Document, nil
}

// _ ensures response.Response is in scope for the import grouping above.
var _ = response.Response{}
