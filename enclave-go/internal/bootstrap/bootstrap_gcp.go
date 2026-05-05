//go:build cloud_gcp

// Package bootstrap: GCP Confidential Space variant.
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
// Required env (set in the workload spec / Confidential Space metadata):
//
//	QUILL_GCP_PROJECT_ID         e.g. "quill-cloud-proxy"
//	QUILL_DEVICE_KEYS_SECRET     name of the secret holding the device-key JSON
//	QUILL_OPENROUTER_SECRET      name of the secret holding the OpenRouter API key (llm_openrouter builds)
//	QUILL_ANTHROPIC_SECRET       name of the secret holding the direct Anthropic API key (llm_anthropic builds)
//	QUILL_TRUSTEDROUTER_INTERNAL_SECRET optional Secret Manager secret name
package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	metadataTokenURL  = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- metadata endpoint URL, not a secret.
	secretManagerHost = "secretmanager.googleapis.com"
)

// Fetch builds BootstrapData by pulling secrets from Google Secret
// Manager. Returns an error if the workload is missing the env vars
// (so a misconfigured deploy fails loudly instead of silently running
// with no devices).
func Fetch(ctx context.Context) (*types.BootstrapData, error) {
	project := os.Getenv("QUILL_GCP_PROJECT_ID")
	if project == "" {
		return nil, fmt.Errorf("bootstrap/gcp: QUILL_GCP_PROJECT_ID not set")
	}
	devicesSecret := os.Getenv("QUILL_DEVICE_KEYS_SECRET")
	if devicesSecret == "" {
		return nil, fmt.Errorf("bootstrap/gcp: QUILL_DEVICE_KEYS_SECRET not set")
	}
	// Each build target needs at least one provider secret set, but bootstrap
	// doesn't know which build it's serving — so we fetch whatever env vars
	// happen to be set. multi builds can set multiple at once; single-backend
	// builds set exactly one. Failing loud below if literally none are set.
	openrouterSecret := os.Getenv("QUILL_OPENROUTER_SECRET")
	anthropicSecret := os.Getenv("QUILL_ANTHROPIC_SECRET")
	kimiSecret := os.Getenv("QUILL_KIMI_SECRET")
	zaiSecret := os.Getenv("QUILL_ZAI_SECRET")
	if openrouterSecret == "" && anthropicSecret == "" && kimiSecret == "" && zaiSecret == "" {
		return nil, fmt.Errorf("bootstrap/gcp: at least one of QUILL_{OPENROUTER,ANTHROPIC,KIMI,ZAI}_SECRET must be set")
	}

	httpc := &http.Client{Timeout: 10 * time.Second}

	token, err := fetchAccessToken(ctx, httpc)
	if err != nil {
		return nil, err
	}

	devicesJSON, err := fetchSecret(ctx, httpc, token, project, devicesSecret)
	if err != nil {
		return nil, fmt.Errorf("bootstrap/gcp: device-keys: %w", err)
	}
	var devices []types.DeviceConfig
	if err := json.Unmarshal(devicesJSON, &devices); err != nil {
		return nil, fmt.Errorf("bootstrap/gcp: parse device-keys JSON: %w", err)
	}

	var openrouterKey []byte
	if openrouterSecret != "" {
		openrouterKey, err = fetchSecret(ctx, httpc, token, project, openrouterSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: openrouter key: %w", err)
		}
	}
	var anthropicKey []byte
	if anthropicSecret != "" {
		anthropicKey, err = fetchSecret(ctx, httpc, token, project, anthropicSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: anthropic key: %w", err)
		}
	}
	var kimiKey []byte
	if kimiSecret != "" {
		kimiKey, err = fetchSecret(ctx, httpc, token, project, kimiSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: kimi key: %w", err)
		}
	}
	var zaiKey []byte
	if zaiSecret != "" {
		zaiKey, err = fetchSecret(ctx, httpc, token, project, zaiSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: zai key: %w", err)
		}
	}
	var internalGatewayToken string
	if internalSecret := os.Getenv("QUILL_TRUSTEDROUTER_INTERNAL_SECRET"); internalSecret != "" {
		value, err := fetchSecret(ctx, httpc, token, project, internalSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: trustedrouter internal token: %w", err)
		}
		internalGatewayToken = string(value)
	}

	return &types.BootstrapData{
		Devices:                    devices,
		Region:                     os.Getenv("QUILL_GCP_REGION"),
		OpenRouterAPIKey:           strings.TrimSpace(string(openrouterKey)),
		AnthropicAPIKey:            strings.TrimSpace(string(anthropicKey)),
		KimiAPIKey:                 strings.TrimSpace(string(kimiKey)),
		ZAIAPIKey:                  strings.TrimSpace(string(zaiKey)),
		TrustedRouterBaseURL:       os.Getenv("TR_CONTROL_PLANE_BASE_URL"),
		TrustedRouterInternalToken: strings.TrimSpace(internalGatewayToken),
		// BedrockVsockProxy / OpenRouterVsockProxy unused on GCP — direct egress.
	}, nil
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

type secretResponse struct {
	Name    string `json:"name"`
	Payload struct {
		Data string `json:"data"` // base64-encoded
	} `json:"payload"`
}

func fetchSecret(ctx context.Context, c *http.Client, token, project, secretName string) ([]byte, error) {
	url := fmt.Sprintf(
		"https://%s/v1/projects/%s/secrets/%s/versions/latest:access",
		secretManagerHost, project, secretName,
	)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secret fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("secret fetch: read error body: %w", readErr)
		}
		return nil, fmt.Errorf("secret fetch http %d: %s", resp.StatusCode, body)
	}
	var sr secretResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(sr.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode secret payload: %w", err)
	}
	return plaintext, nil
}
