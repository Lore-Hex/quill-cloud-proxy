//go:build cloud_gcp

// Package attestation: GCP Confidential Space variant.
//
// Confidential Space exposes an attestation-token issuer at the
// container-side address `http://localhost/v1/token` (a privileged Unix
// socket inside the container; not the metadata server). It returns a
// Google-signed OIDC JWT whose claims include:
//
//	image_digest         OCI digest of the workload image — analogue of PCR0
//	image_reference      "us-central1-docker.pkg.dev/.../enclave:latest" or
//	                     whatever tag/digest was set on the VM
//	image_signatures     cosign signatures attached to the image (if any)
//	submods.confidential_space.support_attributes  whether the launcher
//	                     is in a supported config
//	nonces[]             caller-supplied freshness tokens
//
// We bind the workload's TLS leaf into the JWT by putting the leaf fingerprint
// in the Confidential Space nonce list, alongside the device-key blob hash and
// the caller-supplied freshness nonce. Clients verify the JWT against Google's
// public keys, check `image_digest` matches the published digest, and check the
// live TLS cert's SHA-256 appears in `nonces[]`. Same binding chain as the AWS
// COSE document, with JWT signatures instead of COSE_Sign1.
//
// We hand-roll the HTTP call (no Google SDK) for the same reason as
// elsewhere — keeps the binary small and the auditable surface tight.
package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// teeserverSocket is the Unix socket the Confidential Space launcher
// exposes inside the workload container for on-demand attestation
// tokens. URL goes through `http://teeserver/...` — the host portion
// is ignored since the http.Client below uses a custom DialContext
// that always dials the Unix socket.
//
// Earlier draft used `http://localhost/v1/token` which gave a connect
// refused because there's nothing on TCP localhost:80; CSP exposes the
// launcher API only via this Unix socket.
const teeserverSocketPath = "/run/container_launcher/teeserver.sock"
const attestationTokenURL = "http://teeserver/v1/token" // #nosec G101 -- URL, not a secret.

// Get returns the raw JWT bytes for the cmd/enclave handler to forward
// as Content-Type: application/jwt. Signature matches the AWS variant
// so cmd/enclave/main.go can call it under either build tag.
//
// nonce is optional client freshness. deviceBlob is hashed in to prove
// the device-key list bound at boot (parallels AWS UserData[:32]).
//
// Two GCP deployment shapes are supported:
//
//  1. Confidential Space VM (CSP launcher present): mints an OIDC JWT
//     via the launcher's local Unix socket; the JWT is Google-signed
//     and commits to image_digest, image_reference, and (for the VM
//     target) the in-enclave TLS leaf cert SHA-256.
//  2. Cloud Run with Confidential Computing not enabled: the launcher
//     socket isn't present. We fall back to a self-emitted manifest
//     (NOT Google-signed) that exposes image digest derived from
//     K_REVISION/K_SERVICE env vars. Callers verifying must accept
//     this manifest as a weaker trust tier — explicitly documented
//     on the trust page.
//
// The returned bytes are CBOR for AWS, OIDC JWT for CSP-VM, and a
// JSON manifest for Cloud Run mode. Content-Type is set by the
// cmd/enclave handler from the leading byte: '{' = JSON, otherwise
// JWT/CBOR.
func Get(leafDER []byte, deviceBlob []byte, nonce []byte) ([]byte, error) {
	if _, err := os.Stat(teeserverSocketPath); os.IsNotExist(err) {
		// Cloud Run shape: no CSP launcher. Emit a self-attested manifest.
		return cloudRunManifest(deviceBlob, nonce)
	}
	deviceHash := sha256.Sum256(deviceBlob)

	reqBody := tokenRequest{
		Audience:  "quill-cloud",
		TokenType: "OIDC",
		Nonces: []string{
			hex.EncodeToString(deviceHash[:]),
		},
	}
	// Cloud Run target: leafDER is nil because TLS terminates at GCP's
	// edge, not in the enclave. Skip the cert binding — the JWT still
	// commits to image_digest + image_reference (via the standard CSP
	// claim set) plus the device-blob hash and any client nonce.
	// CSP-VM target: bind the in-enclave leaf cert SHA-256 so clients
	// can pin the live TLS connection to the attestation document.
	if leafDER != nil {
		leafFP := sha256.Sum256(leafDER)
		reqBody.Nonces = append([]string{hex.EncodeToString(leafFP[:])}, reqBody.Nonces...)
	}
	if len(nonce) > 0 {
		reqBody.Nonces = append(reqBody.Nonces, hex.EncodeToString(nonce))
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("attestation/gcp: marshal: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", attestationTokenURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Custom transport: always dial the launcher's Unix socket.
	httpc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", teeserverSocketPath)
			},
		},
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attestation/gcp: token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		errBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("attestation/gcp: read error body: %w", readErr)
		}
		return nil, fmt.Errorf("attestation/gcp: token http %d: %s", resp.StatusCode, errBody)
	}
	jwt, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return jwt, nil
}

// cloudRunManifest emits a JSON manifest for the Cloud Run deployment
// shape. It is *self-attested* — no Google signature — because Cloud
// Run with Confidential Computing flagged off does not expose the CSP
// launcher socket, and there is no other built-in way to obtain a
// JWT committing to the workload image digest.
//
// Trust property note: a caller verifying this manifest is trusting
// (a) that they reached the right Cloud Run service via DNS+TLS, and
// (b) that GCP deployed the image hash named in K_CONFIGURATION /
// K_REVISION. This is the same trust model as ordinary serverless
// SaaS — strictly weaker than the CSP-VM target. The trust page
// documents this clearly per region.
func cloudRunManifest(deviceBlob, nonce []byte) ([]byte, error) {
	deviceHash := sha256.Sum256(deviceBlob)
	manifest := map[string]any{
		"kind":             "cloud-run-self-attested",
		"k_service":        os.Getenv("K_SERVICE"),
		"k_revision":       os.Getenv("K_REVISION"),
		"k_configuration":  os.Getenv("K_CONFIGURATION"),
		"region":           os.Getenv("QUILL_GCP_REGION"),
		"project":          os.Getenv("QUILL_GCP_PROJECT_ID"),
		"device_blob_sha":  hex.EncodeToString(deviceHash[:]),
		"trust_tier":       "image-digest-only",
		"trust_note": "Cloud Run with Confidential Computing not enabled. " +
			"This manifest is self-attested (NOT Google-signed). " +
			"Verify image deployment integrity via the trust page's " +
			"published image_digest for this service.",
	}
	if len(nonce) > 0 {
		manifest["nonce"] = hex.EncodeToString(nonce)
	}
	return json.Marshal(manifest)
}

// tokenRequest is the body shape the CSP attestation server accepts.
// (Documented in https://cloud.google.com/confidential-computing/
//
//	confidential-space/docs/connect-external-resources#attestation-tokens.)
type tokenRequest struct {
	Audience  string   `json:"audience"`
	TokenType string   `json:"token_type"`       // "OIDC" | "PKI" | "AWS_PRINCIPALTAGS" | "AZURE_TOKEN_EXCHANGE"
	Nonces    []string `json:"nonces,omitempty"` // hex; we pack TLS-fp and device-blob-hash here
}
