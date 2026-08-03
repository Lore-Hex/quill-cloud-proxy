//go:build cloud_gcp

// Package bootstrap: GCP Confidential Space variant.
//
// See bootstrap_aws.go for the per-cloud-file layout pattern this
// package follows. Each cloud has its own bootstrap_<cloud>.go with a
// matching `//go:build` tag; the linker picks one at compile time
// based on the `-tags cloud_<cloud>` build flag.
//
// Trust posture differs from the AWS variant in an important way:
//
// AWS:
//
//	The parent (a separate process on the EC2 host) reads the sealed
//	device blob from S3 + KMS-decrypts on behalf of the enclave, then
//	ships plaintext over vsock. The parent therefore *sees* the device
//	list and the Bedrock credentials in plaintext for ~ms at boot.
//	V1 trust caveat documented on the trust page.
//
// GCP:
//
//	The workload IS the only thing on the box (Confidential Space is a
//	single-container model — no sidecar, no parent). It calls Google
//	Secret Manager directly via the metadata-server-issued workload
//	identity token. The KMS attestation condition gates secret access
//	to "only an attested workload at the published image digest can
//	read this secret" — strictly stronger than the V1 AWS posture.
//
// Wire layout:
//  1. GET http://metadata.google.internal/computeMetadata/v1/instance/
//     service-accounts/default/identity?audience=...
//     → returns an OIDC ID token (NOT an access token; see attestation_gcp.go).
//  2. GET .../instance/service-accounts/default/token
//     → returns an access token usable as a Bearer.
//  3. GET https://secretmanager.googleapis.com/v1/projects/$PROJECT/
//     secrets/$NAME/versions/latest:access  Authorization: Bearer ...
//     → returns {"payload":{"data":"<base64>"}}
//
// Step 3 — and every secret name, fetch order, and BootstrapData field it
// feeds — lives in secrets_google.go, shared with the Azure adapter. This file
// owns exactly one thing that is GCP-specific: obtaining the access token from
// the metadata server. Everything else must stay in the shared file so the two
// self-fetching clouds cannot drift apart.
//
// Required env (set in the workload spec / Confidential Space metadata):
//
//	QUILL_GCP_PROJECT_ID         e.g. "quill-cloud-proxy"
//	QUILL_DEVICE_KEYS_SECRET     name of the secret holding the device-key JSON
//	QUILL_OPENROUTER_SECRET      name of the OpenRouter key secret (llm_openrouter and Muse-on-multi)
//	QUILL_ANTHROPIC_SECRET       name of the secret holding the direct Anthropic API key (llm_anthropic builds)
//	QUILL_OPENAI_SECRET          name of the secret holding the OpenAI API key (llm_multi builds)
//	QUILL_GEMINI_SECRET          name of the secret holding the Gemini API key (llm_multi builds)
//	QUILL_CEREBRAS_SECRET        name of the secret holding the Cerebras API key (llm_multi builds)
//	QUILL_DEEPSEEK_SECRET        name of the secret holding the DeepSeek API key (llm_multi builds)
//	QUILL_MISTRAL_SECRET         name of the secret holding the Mistral API key (llm_multi builds)
//	QUILL_FIREWORKS_SECRET       name of the secret holding the Fireworks API key (llm_multi builds)
//	QUILL_FRIENDLI_SECRET        name of the secret holding the Friendli API key (llm_multi builds)
//	QUILL_BASETEN_SECRET         name of the secret holding the Baseten API key (llm_multi builds)
//	QUILL_WAFER_SECRET           name of the secret holding the Wafer API key (llm_multi builds)
//	QUILL_CRUSOE_SECRET          name of the secret holding the Crusoe API key (llm_multi builds)
//	QUILL_MAKORA_SECRET          name of the secret holding the Makora API key (llm_multi builds)
//	QUILL_SYNTH_PANEL_PROMPT_SECRET           name of the secret holding the default synth panel prompt
//	QUILL_SYNTH_SYNTHESIS_PROMPT_SECRET       name of the secret holding the default synth synthesis prompt
//	QUILL_SYNTH_CODE_PANEL_PROMPT_SECRET      name of the secret holding the synth-code panel prompt
//	QUILL_SYNTH_CODE_SYNTHESIS_PROMPT_SECRET  name of the secret holding the synth-code synthesis prompt
//	QUILL_ADVISOR_WORKER_PROMPT_SECRET        name of the secret holding the advisor worker prompt
//	QUILL_ADVISOR_PROMPT_SECRET               name of the secret holding the advisor prompt
//	QUILL_TRUSTEDROUTER_INTERNAL_SECRET optional Secret Manager secret name
//
// The full, authoritative list is the secretBindings table in
// secrets_google.go.
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const metadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- metadata endpoint URL, not a secret.

// Fetch builds BootstrapData by pulling secrets from Google Secret
// Manager. Returns an error if the workload is missing the env vars
// (so a misconfigured deploy fails loudly instead of silently running
// with no devices).
func Fetch(ctx context.Context) (*types.BootstrapData, error) {
	// Environment first, before any I/O: a deploy missing
	// QUILL_GCP_PROJECT_ID must say so rather than surfacing whatever the
	// metadata server happens to return.
	cfg, err := resolveSecretConfig("bootstrap/gcp")
	if err != nil {
		return nil, err
	}

	httpc := &http.Client{Timeout: 10 * time.Second}

	token, err := fetchAccessToken(ctx, httpc)
	if err != nil {
		return nil, err
	}

	return fetchBootstrapSecrets(ctx, httpc, token, cfg, "bootstrap/gcp")
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func fetchAccessToken(ctx context.Context, c *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", metadataTokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("bootstrap/gcp: metadata token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", fmt.Errorf("bootstrap/gcp: read metadata token error body: %w", readErr)
		}
		return "", fmt.Errorf("bootstrap/gcp: metadata token http %d: %s", resp.StatusCode, body)
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("bootstrap/gcp: decode token: %w", err)
	}
	return tr.AccessToken, nil
}
