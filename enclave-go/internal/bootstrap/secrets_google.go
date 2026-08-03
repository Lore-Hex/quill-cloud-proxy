//go:build cloud_gcp

// Google Secret Manager transport — GCP ONLY.
//
// This file is the HTTP half of the GCP adapter: one authenticated GET per
// secret against secretmanager.googleapis.com. The names it fetches, their
// order, and where their values land in BootstrapData all live in secrets.go,
// shared with Azure.
//
// The build tag is load-bearing. It was `cloud_gcp || cloud_azure` while the
// Azure enclave unwrapped a GCP service-account key under attestation and then
// read all ~40 secrets from this endpoint. That made an Azure boot depend on
// Google being up, which voids the independence a second cloud exists to
// provide, so Azure now keeps its own copies in Key Vault (bootstrap_azure.go).
// Narrowing the tag is what makes that structural rather than a convention: the
// OAuth machinery and the googleapis.com host are not merely unused under
// cloud_azure, they are not compiled.
//
// (Deliberately detached from the package clause below — the package doc lives
// on whichever per-cloud adapter file the build tag selected.)

package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// secretManagerHost is the production endpoint. It is a const so that the
// value cannot be edited away; the var below only exists to be redirected.
const secretManagerHost = "https://secretmanager.googleapis.com"

// secretManagerBaseURL is a var rather than a const purely so tests can point
// the fetch loop at an httptest server (the same "swappable seam" convention
// attestation_azure.go uses for requestToken). Production never rewrites it: it
// is unexported and reachable from no env var, flag, or request path, and
// TestSecretManagerBaseURLDefaultsToProduction fails if it stops equalling
// secretManagerHost.
var secretManagerBaseURL = secretManagerHost

// maxSecretResponseBytes bounds both the Secret Manager error body and the
// success body. Secret Manager caps a payload at 64 KiB, which base64-expands
// to ~88 KiB inside a small JSON wrapper.
const maxSecretResponseBytes = 1 << 20

// fetchBootstrapSecrets pulls every configured secret with the supplied Google
// access token and assembles BootstrapData. The token is the ONLY cloud-
// specific input; how it was obtained is the caller's business.
func fetchBootstrapSecrets(ctx context.Context, httpc *http.Client, token string, cfg secretConfig, tag string) (*types.BootstrapData, error) {
	return assembleBootstrapData(ctx, cfg, tag, func(ctx context.Context, name string) ([]byte, error) {
		return fetchSecret(ctx, httpc, token, cfg.project, name)
	})
}

type secretResponse struct {
	Name    string `json:"name"`
	Payload struct {
		Data string `json:"data"` // base64-encoded
	} `json:"payload"`
}

func fetchSecret(ctx context.Context, c *http.Client, token, project, secretName string) ([]byte, error) {
	url := fmt.Sprintf(
		"%s/v1/projects/%s/secrets/%s/versions/latest:access",
		secretManagerBaseURL, project, secretName,
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
		// Safe to echo: a non-200 body is Google's error envelope, never the
		// secret. The 200 path below deliberately echoes nothing. Bounded so a
		// misbehaving upstream cannot turn one error into an unbounded
		// allocation on the boot path.
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return nil, fmt.Errorf("secret fetch: read error body: %w", readErr)
		}
		return nil, fmt.Errorf("secret fetch http %d: %s", resp.StatusCode, body)
	}
	var sr secretResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSecretResponseBytes)).Decode(&sr); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(sr.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode secret payload: %w", err)
	}
	return plaintext, nil
}
