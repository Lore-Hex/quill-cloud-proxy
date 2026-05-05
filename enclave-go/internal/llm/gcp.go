//go:build llm_vertex || llm_multi

// Google Vertex AI provider — hand-rolled minimal client.
//
// Why not the official anthropic-sdk-go/vertex backend?
// It pulls in golang.org/x/oauth2/google + cloud.google.com/go/auth +
// google.golang.org/api/transport, which transitively drag in gRPC,
// protobuf, and OpenTelemetry — adding ~14 MB to the binary for an
// HTTPS endpoint we can hit in ~150 lines of net/http.
//
// What we actually need on Confidential Space:
//  1. An access token. Inside a Confidential Space VM, the GCE metadata
//     server hands one out via Workload Identity Federation; no OAuth
//     flow, no client secret, no library. One GET request.
//  2. An HTTPS POST to Vertex with the Anthropic Messages body wrapped
//     with `anthropic_version: vertex-2023-10-16`.
//  3. The response is already native Anthropic SSE; the existing
//     adapter package downstream parses it without changes.
//
// That's ~150 lines of net/http. Smaller binary, smaller measurement,
// smaller audit surface.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	// metadataTokenURL is the GCE metadata server's token endpoint. Same
	// inside Confidential Space — Workload Identity Federation issues a
	// short-lived token bound to the workload's service account, scoped
	// to the workload's attestation evidence.
	metadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- metadata endpoint URL, not a secret.

	// vertexAnthropicVersion is the value Vertex requires in the request
	// body in place of the anthropic-version HTTP header used by the
	// direct Anthropic API.
	vertexAnthropicVersion = "vertex-2023-10-16"
)

type gcpClient struct {
	projectID string
	region    string // "global", "us-east1", etc.
	httpc     *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// fetchToken pulls a fresh access token from the GCE metadata server.
// Tokens are cached until ~30 s before expiry to avoid bouncing the
// metadata server on every request.
func (c *gcpClient) fetchToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExp.Add(-30*time.Second)) {
		return c.token, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", metadataTokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm/gcp: metadata token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", fmt.Errorf("llm/gcp: read metadata token error body: %w", readErr)
		}
		return "", fmt.Errorf("llm/gcp: metadata token http %d: %s", resp.StatusCode, body)
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("llm/gcp: decode token: %w", err)
	}
	c.token = tr.AccessToken
	c.tokenExp = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.token, nil
}

// vertexHost returns the API host for the configured region. "global" is
// special-cased to the regionless aiplatform.googleapis.com endpoint.
func (c *gcpClient) vertexHost() string {
	if c.region == "global" || c.region == "" {
		return "aiplatform.googleapis.com"
	}
	if c.region == "us" || c.region == "eu" {
		return fmt.Sprintf("aiplatform.%s.rep.googleapis.com", c.region)
	}
	return fmt.Sprintf("%s-aiplatform.googleapis.com", c.region)
}

func (c *gcpClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if handled, err := invokeBYOKStreaming(ctx, req, body, out, firstOptions(options)); handled {
		return err
	}
	token, err := c.fetchToken(ctx)
	if err != nil {
		return err
	}

	// Build the Vertex-shaped request body. Identical to Anthropic's
	// Messages API except `anthropic_version` is in the body and `model`
	// goes into the URL.
	reqBody := struct {
		AnthropicVersion string                    `json:"anthropic_version"`
		Messages         []qtypes.AnthropicMessage `json:"messages"`
		System           string                    `json:"system,omitempty"`
		MaxTokens        int                       `json:"max_tokens"`
		Temperature      *float64                  `json:"temperature,omitempty"`
		TopP             *float64                  `json:"top_p,omitempty"`
		Stream           bool                      `json:"stream"`
	}{
		AnthropicVersion: vertexAnthropicVersion,
		Messages:         body.Messages,
		System:           body.System,
		MaxTokens:        body.MaxTokens,
		Temperature:      body.Temperature,
		TopP:             body.TopP,
		Stream:           true,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("llm/gcp: marshal body: %w", err)
	}

	url := fmt.Sprintf(
		"https://%s/v1/projects/%s/locations/%s/publishers/anthropic/models/%s:streamRawPredict",
		c.vertexHost(), c.projectID, c.region, req.Model,
	)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/gcp: invoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		errBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("llm/gcp: read vertex error body: %w", readErr)
		}
		return fmt.Errorf("llm/gcp: vertex http %d: %s", resp.StatusCode, errBody)
	}
	// The response is already Anthropic-native SSE bytes. Just pump them
	// through to the adapter — no re-emission needed.
	_, err = io.Copy(out, resp.Body)
	return err
}

// newVertex constructs the Vertex-direct client. Used as THE Client in
// single-backend builds (register_vertex.go) and as ONE OF the available
// clients in multi-backend builds (multi.go).
func newVertex(boot *qtypes.BootstrapData) *gcpClient {
	projectID := os.Getenv("QUILL_GCP_PROJECT_ID")
	region := os.Getenv("QUILL_GCP_REGION")
	if region == "" {
		region = "global"
	}
	return &gcpClient{
		projectID: projectID,
		region:    region,
		httpc: &http.Client{
			Timeout: 10 * time.Minute, // long-running streams
		},
	}
}
