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
func Get(leafDER []byte, deviceBlob []byte, nonce []byte) ([]byte, error) {
	leafFP := sha256.Sum256(leafDER)
	deviceHash := sha256.Sum256(deviceBlob)

	reqBody := tokenRequest{
		Audience:  "quill-cloud",
		TokenType: "OIDC",
		Nonces: []string{
			hex.EncodeToString(leafFP[:]),
			hex.EncodeToString(deviceHash[:]),
		},
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

// tokenRequest is the body shape the CSP attestation server accepts.
// (Documented in https://cloud.google.com/confidential-computing/
//
//	confidential-space/docs/connect-external-resources#attestation-tokens.)
type tokenRequest struct {
	Audience  string   `json:"audience"`
	TokenType string   `json:"token_type"`       // "OIDC" | "PKI" | "AWS_PRINCIPALTAGS" | "AZURE_TOKEN_EXCHANGE"
	Nonces    []string `json:"nonces,omitempty"` // hex; we pack TLS-fp and device-blob-hash here
}
