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
//	x-ms-sevsnpvm-reportdata   sha256(runtime_data) || 32 zero bytes,
//	                           computed by the sidecar (see below)
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
// SEV-SNP gives 64 bytes of REPORT_DATA. We do NOT compute it: the sidecar
// does, as sha256(runtime_data) followed by 32 zero bytes. Any report_data we
// send is ignored. The pre-image is what we control, and it carries the same
// four inputs the other backends bind — TLS leaf fingerprint, device blob,
// client nonce, and the channel binding that ties the attestation to the live
// TLS session. MAA echoes the pre-image back in the token so a verifier can
// recompute the digest and confirm the report commits to these exact values.
//
// FIELD ORDER IS LOAD-BEARING, and not for style reasons. MAA does not echo
// runtime_data as the bytes we sent; it re-serialises it as a JSON object with
// keys in ALPHABETICAL order. The original byte order is therefore destroyed
// in transit, and a verifier recomputing sha256 over the echoed object can only
// ever reproduce the sorted form. So we emit sorted-by-key JSON in the first
// place: encoding/json writes struct fields in declaration order, and these
// fields are declared alphabetically so the emitted bytes already equal what a
// verifier reconstructs. Reordering this struct silently breaks verification of
// every token — the hash stops matching and nothing else changes.
//
// MEASURED, not assumed. Verified 2026-08-03 against a real SEV-SNP
// confidential container group in Azure UAE North (skr sidecar 2.7):
//
//	x-ms-sevsnpvm-hostdata     == the CCE policy hash from `az confcom
//	                              acipolicygen`, and it CHANGED when the
//	                              container command changed, so it genuinely
//	                              measures this workload
//	x-ms-sevsnpvm-reportdata   == sha256(runtime_data) || 32 zero bytes
//	x-ms-runtime               == a JSON OBJECT with sorted keys, not the
//	                              base64 string that was sent
//	x-ms-sevsnpvm-is-debuggable== false
//
// The first draft of this file computed SHA-512 into REPORT_DATA and declared
// the fields in a non-sorted order. Both were reasonable readings of the
// documentation and both are wrong against the real endpoint: no token would
// ever have verified. That is the live-transport lesson from the GCP rollout
// repeating itself, which is why these values are now pinned by a real-token
// fixture in tools/test_verify_attestation_maa.py rather than by reasoning.
package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
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
// Port 8080, measured against skr sidecar 2.7 in UAE North: its log reads
// "Listening and serving HTTP on localhost:8080". An earlier draft used 8284,
// which appears in some Azure samples; against this sidecar every request
// would have been refused. Override with QUILL_AZURE_ATTESTATION_URL if a
// future sidecar moves it again.
const defaultSidecarURL = "http://localhost:8080/attest/maa"

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
// Fields are declared in ALPHABETICAL order on purpose — see the package
// comment. MAA re-serialises this object with sorted keys, so emitting sorted
// bytes is the only way a verifier can recompute sha256 over what the hardware
// actually committed to. Do not reorder.
type runtimeData struct {
	ChannelBinding  string `json:"channel_binding,omitempty"`
	DeviceHash      string `json:"device_hash"`
	LeafFingerprint string `json:"leaf_fp"`
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

	// encoding/json emits struct fields in declaration order, and the fields
	// are declared alphabetically, so this is already the sorted-key form a
	// verifier reconstructs from MAA's echoed object.
	rdJSON, err := json.Marshal(rd)
	if err != nil {
		return tokenRequest{}, fmt.Errorf("attestation/azure: marshal runtime data: %w", err)
	}

	// No report_data is sent. The sidecar computes REPORT_DATA itself as
	// sha256(runtime_data) || 32 zero bytes and ignores anything supplied
	// here, so sending a digest would only invite the belief that this side
	// chose it.
	return tokenRequest{
		MAAEndpoint: maaEndpoint(),
		RuntimeData: base64.StdEncoding.EncodeToString(rdJSON),
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
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("attestation/azure: read token: %w", err)
	}
	// UNWRAP the sidecar's `{"token": "<JWT>"}` envelope.
	//
	// /attestation's wire contract is a BARE attestation document: GCP
	// Confidential Space serves the OIDC JWT itself, AWS Nitro serves the
	// COSE_Sign1 bytes, and every client — tools/verify-attestation.py, the
	// SDKs, the synthetic probes — sniffs the first bytes to decide which.
	// Passing the sidecar's envelope through verbatim made Azure the only
	// cloud whose document arrived wrapped, so the sniff fell through to the
	// CBOR branch and every verification died inside a CBOR parser with a
	// message about truncated input — pointing at the transport rather than
	// at the shape. The envelope is the SIDECAR's contract, not ours.
	return unwrapSidecarToken(raw)
}

// unwrapSidecarToken returns the bare JWT from the guest-attestation
// sidecar's JSON envelope, tolerating a bare token in case a future sidecar
// version stops wrapping.
func unwrapSidecarToken(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("attestation/azure: sidecar returned an empty body")
	}
	if trimmed[0] != '{' {
		return trimmed, nil
	}
	var envelope struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return nil, fmt.Errorf("attestation/azure: sidecar body is neither a token nor JSON: %w", err)
	}
	if envelope.Token == "" {
		// Deliberately does not echo the body: it is attestation material.
		return nil, fmt.Errorf("attestation/azure: sidecar JSON has no non-empty \"token\"")
	}
	return []byte(envelope.Token), nil
}

// tokenRequest is the body the Azure guest-attestation sidecar accepts.
type tokenRequest struct {
	MAAEndpoint string `json:"maa_endpoint"`
	RuntimeData string `json:"runtime_data"`
}
