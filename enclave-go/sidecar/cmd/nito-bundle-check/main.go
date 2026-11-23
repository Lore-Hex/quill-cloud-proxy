// Verify one Nito-relayed Tinfoil bundle, not inference or a privacy tier.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

const routerRepo = "tinfoilsh/confidential-model-router"
const maxBundle = 4_000_000

var (
	routerHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.tinfoil\.sh$`)
	digestHex  = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func verify(input io.Reader, digest string, now time.Time) (*client.GroundTruth, error) {
	if !digestHex.MatchString(digest) {
		return nil, errors.New("provide the independently obtained router release digest")
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxBundle+1))
	var evidence struct {
		Bundle attestation.Bundle `json:"bundle"`
		Claim  client.GroundTruth `json:"verification"`
	}
	if err != nil || len(raw) > maxBundle || json.Unmarshal(raw, &evidence) != nil {
		return nil, errors.New("invalid or oversized evidence")
	}
	b := evidence.Bundle
	if b.EnclaveAttestationReport == nil || b.EnclaveAttestationReport.Format != attestation.SevGuestV2 ||
		b.EnclaveAttestationReport.Body == "" || b.VCEK == "" || len(b.SigstoreBundle) == 0 {
		return nil, errors.New("missing or unsupported bundle")
	}
	if b.Digest != digest || !routerHost.MatchString(b.Domain) {
		return nil, errors.New("unexpected release digest or enclave domain")
	}
	block, rest := pem.Decode([]byte(b.EnclaveCert))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, errors.New("invalid enclave certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, errors.New("invalid or expired enclave certificate")
	}
	truth, err := client.NewSecureClient(b.Domain, routerRepo).VerifyFromBundle(&b)
	if err != nil {
		// Verification errors can contain device identity, keys and certificates.
		return nil, errors.New("signed source, hardware, measurement or certificate verification failed")
	}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if truth.EnclaveHost != b.Domain || truth.Digest != digest || !digestHex.MatchString(truth.HPKEPublicKey) ||
		hex.EncodeToString(spki[:]) != truth.TLSPublicKey {
		return nil, errors.New("enclave transport keys or identity mismatch")
	}
	if !sameTransport(truth, &evidence.Claim) {
		return nil, errors.New("relay transport identity differs from verified bundle")
	}
	return truth, nil
}

func sameTransport(verified, claimed *client.GroundTruth) bool {
	return verified.EnclaveHost == claimed.EnclaveHost && verified.Digest == claimed.Digest &&
		verified.HPKEPublicKey == claimed.HPKEPublicKey && verified.TLSPublicKey == claimed.TLSPublicKey
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: nito-bundle-check <independent current router digest> < evidence.json")
		os.Exit(2)
	}
	if _, err := verify(os.Stdin, os.Args[1], time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(`{"tinfoil_bundle_verified":true,"inference_verified":false,"trustedrouter_confidential":false}`)
}
