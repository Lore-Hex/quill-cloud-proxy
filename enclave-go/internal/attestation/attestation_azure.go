//go:build cloud_azure

// Package attestation: Azure Confidential Computing (AMD SEV-SNP) variant.
//
// Azure's confidential containers run on AMD SEV-SNP hardware and ship a
// guest-attestation sidecar alongside the workload. The sidecar reads the
// hardware SNP report via /dev/sev-guest, forwards it to Microsoft Azure
// Attestation (MAA), and returns MAA's signed JWT. Claims include:
//
//	x-ms-sevsnpvm-hostdata     the container/policy measurement bound at
//	                           launch — the analogue of GCP's image_digest
//	                           and Nitro's PCR0
//	x-ms-sevsnpvm-is-debuggable false on a properly locked-down guest
//	x-ms-sevsnpvm-reportdata   the 64 bytes WE supply (see below)
//	x-ms-attestation-type      "sevsnpvm"
//
// Why this backend resembles the GCP one and not the AWS one
// ----------------------------------------------------------
// Nitro returns a CBOR/COSE attestation document that the verifier parses
// itself. Both Confidential Space and MAA instead return a *signed JWT* from
// a cloud-operated issuer, verified against that issuer's JWKS. So the
// verifier-side shape here is the GCP shape, and this file is deliberately a
// close structural mirror of attestation_gcp.go — same Get() signature, same
// "hash the caller's bindings and hand them to a local issuer" flow, same
// swappable requestToken seam for tests.
//
// Binding (the part that must not be got wrong)
// ---------------------------------------------
// SEV-SNP gives exactly 64 bytes of caller-controlled REPORT_DATA. That is
// the only field cryptographically bound into the hardware report, so
// everything we need to prove must be reduced into it. We hash the same four
// inputs the other backends bind — TLS leaf fingerprint, device blob, client
// nonce, and the channel binding that ties the attestation to the live TLS
// session — into a single SHA-512 digest, which is exactly 64 bytes and fills
// REPORT_DATA without truncation.
//
// The full pre-image is ALSO sent as runtime_data so a verifier can recompute
// the digest and confirm the report commits to these specific values; MAA
// echoes it back in the token. Sending only the digest would leave a verifier
// unable to tell WHAT was bound.
//
// STATUS: written against Azure's documented guest-attestation contract but
// NOT yet exercised on real SEV-SNP hardware — there is no Azure environment
// to run it in yet. The unit tests cover request construction and the error
// paths through the injectable seam; the live-transport behaviour is exactly
// the class of thing that only shows up against the real endpoint (see the
// verifier live-transport lesson from the GCP rollout), so treat a first
// deployment as a real bring-up, not a formality.
package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// The guest-attestation sidecar listens on localhost inside the pod. Both the
// address and the MAA instance are environment-driven: MAA endpoints are
// per-region and per-tenant, and hardcoding either would make the image
// non-portable across regions.
const defaultSidecarURL = "http://localhost:8284/attest/maa"

func sidecarURL() string {
	if v := os.Getenv("QUILL_AZURE_ATTESTATION_URL"); v != "" {
		return v
	}
	return defaultSidecarURL
}

func maaEndpoint() string {
	return os.Getenv("QUILL_AZURE_MAA_ENDPOINT")
}

var requestToken = requestTokenFromSidecar

// Get returns the raw MAA JWT bytes for the cmd/enclave handler to forward as
// Content-Type: application/jwt. The signature matches the GCP and AWS
// variants so cmd/enclave/main.go compiles unchanged under any build tag.
func Get(leafDER []byte, deviceBlob []byte, nonce []byte, channelBinding []byte) ([]byte, error) {
	reqBody, err := buildTokenRequest(leafDER, deviceBlob, nonce, channelBinding)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("attestation/azure: marshal: %w", err)
	}
	return requestToken(body)
}

// runtimeData is the pre-image bound into the SEV-SNP report.
//
// Field names and hex encoding intentionally match the values the GCP backend
// packs into its `nonces` array, so a verifier can apply one rule across both
// clouds instead of learning a per-cloud layout.
type runtimeData struct {
	LeafFingerprint string `json:"leaf_fp"`
	DeviceHash      string `json:"device_hash"`
	ChannelBinding  string `json:"channel_binding,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
}

func buildTokenRequest(leafDER []byte, deviceBlob []byte, nonce []byte, channelBinding []byte) (tokenRequest, error) {
	leafFP := sha256.Sum256(leafDER)
	deviceHash := sha256.Sum256(deviceBlob)

	rd := runtimeData{
		LeafFingerprint: hex.EncodeToString(leafFP[:]),
		DeviceHash:      hex.EncodeToString(deviceHash[:]),
	}
	if len(channelBinding) > 0 {
		rd.ChannelBinding = hex.EncodeToString(channelBinding)
	}
	if len(nonce) > 0 {
		rd.Nonce = hex.EncodeToString(nonce)
	}

	// Marshal deterministically: the verifier recomputes REPORT_DATA from
	// this exact byte string, so any re-ordering would break verification.
	// encoding/json emits struct fields in declaration order, which is stable.
	rdJSON, err := json.Marshal(rd)
	if err != nil {
		return tokenRequest{}, fmt.Errorf("attestation/azure: marshal runtime data: %w", err)
	}

	// SHA-512 is exactly 64 bytes — the full width of SEV-SNP REPORT_DATA —
	// so nothing is truncated and no padding scheme has to be agreed on.
	digest := sha512.Sum512(rdJSON)

	return tokenRequest{
		MAAEndpoint: maaEndpoint(),
		RuntimeData: base64.StdEncoding.EncodeToString(rdJSON),
		ReportData:  base64.StdEncoding.EncodeToString(digest[:]),
	}, nil
}

func requestTokenFromSidecar(body []byte) ([]byte, error) {
	if maaEndpoint() == "" {
		// Fail loudly rather than letting the sidecar pick a default
		// instance: which MAA instance signed a token is part of the trust
		// decision, and silently attesting against an unintended one would
		// produce tokens that look valid but chain to the wrong authority.
		return nil, fmt.Errorf("attestation/azure: QUILL_AZURE_MAA_ENDPOINT is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", sidecarURL(), strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	httpc := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attestation/azure: token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		errBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("attestation/azure: read error body: %w", readErr)
		}
		return nil, fmt.Errorf("attestation/azure: token http %d: %s", resp.StatusCode, errBody)
	}
	return io.ReadAll(resp.Body)
}

// tokenRequest is the body the Azure guest-attestation sidecar accepts.
type tokenRequest struct {
	MAAEndpoint string `json:"maa_endpoint"`
	RuntimeData string `json:"runtime_data"`
	ReportData  string `json:"report_data,omitempty"`
}
