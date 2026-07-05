//go:build cloud_aws

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
// We bind the document to our TLS leaf cert and live TLS session by setting:
//   - PublicKey = DER-encoded SubjectPublicKeyInfo of the leaf
//   - UserData  = SHA-256 of the leaf cert in DER form (redundant but
//     lets clients use a cheap hash check), the device-key blob hash, and
//     when available the RFC 9266 tls-exporter channel binding
//
// Result: a client can fetch the attestation doc, verify it against AWS's
// root, check PCR0 against the trust page, and check the cert presented in
// their live TLS handshake matches the document's PublicKey and same-session
// exporter. A relay's separate client-facing TLS session has a different
// exporter, closing G6 for the AWS shape too.
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

type nsmSession interface {
	Send(request.Request) (response.Response, error)
	Close() error
}

var openNSMSession = func() (nsmSession, error) {
	return nsm.OpenDefaultSession()
}

// Get returns a fresh attestation document binding the live cryptographic
// state of the enclave into a single NSM-signed COSE blob.
//
// PublicKey: the TLS leaf cert's SubjectPublicKeyInfo. Lets the client
//
//	verify "the cert in this TLS handshake is the cert this PCR0 attests
//	to."
//
// UserData: a 64- or 96-byte structure encoding additional layer-7 commitments —
//
//	{ sha256(leaf cert) || sha256(device-key blob) [|| tls-exporter] }.
//	The device-key hash
//	binds the attestation to the exact set of authorized bearer tokens
//	currently loaded in memory; rotating the device blob produces a new
//	attestation, so a recipient can be sure their bearer token isn't
//	silently being honoured by a stale cached set. The exporter is a distinct
//	RFC 9266 commitment to the live TLS session, not caller-controlled nonce
//	material.
//
// Nonce: caller-supplied freshness — the doc was generated for *their*
//
//	request, not replayed.
func Get(leafDER []byte, deviceBlob []byte, nonce []byte, channelBinding []byte) ([]byte, error) {
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

	// 64 or 96 bytes: cert fingerprint || device-blob fingerprint
	// [|| RFC 9266 exporter]. The exporter is already 32 bytes of keying
	// material derived from the enclave's live TLS session.
	certFP := sha256.Sum256(leafDER)
	var blobFP [32]byte
	if deviceBlob != nil {
		blobFP = sha256.Sum256(deviceBlob)
	}
	userData := make([]byte, 0, 96)
	userData = append(userData, certFP[:]...)
	userData = append(userData, blobFP[:]...)
	if len(channelBinding) > 0 {
		userData = append(userData, channelBinding...)
	}

	sess, err := openNSMSession()
	if err != nil {
		return nil, fmt.Errorf("attestation: open NSM: %w", err)
	}
	defer sess.Close()

	resp, err := sess.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  userData,
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
