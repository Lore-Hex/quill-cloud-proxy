//go:build llm_anthropic || llm_multi

// Direct Anthropic provider — hand-rolled minimal client.
//
// Why direct Anthropic (vs Bedrock / Vertex / OpenRouter)?
//
//   - **No third-party hops.** Bytes flow enclave → api.anthropic.com,
//     TLS terminated at both ends. No OpenRouter middlebox, no Vertex
//     wrapping, no Bedrock proxying. The only extra trust party is
//     Anthropic themselves — same as Bedrock or Vertex transitively.
//   - **Lowest latency.** One HTTP hop instead of two. Saves the
//     OpenRouter→Vertex bounce (~150ms) we observed.
//   - **No region quota dance.** Anthropic's API is globally available
//     from day one; no need for Vertex Anthropic quota approval per
//     project.
//
// Trust caveats (also documented on the trust page):
//
//   - Anthropic sees prompt bytes in plaintext (their TLS endpoint
//     decrypts them). This is true for Bedrock and Vertex too —
//     "the model provider sees the prompt" is intrinsic.
//   - The Anthropic API key is released to the enclave through the
//     same KMS-attested bootstrap channel as the OpenRouter key on
//     other builds.
//
// Wire layout:
//
//	The enclave egresses directly. POST https://api.anthropic.com/v1/messages
//	with Anthropic Messages JSON, header `x-api-key`, header
//	`anthropic-version: 2023-06-01`. Response is native Anthropic SSE
//	bytes which the existing adapter package downstream parses without
//	changes.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	anthropicURL           = "https://api.anthropic.com/v1/messages"
	anthropicVersionHeader = "2023-06-01" // stable; bump only when Anthropic deprecates this version
)

// modelIDMap turns the Quill-public model name into Anthropic's official
// model id. Anthropic's id scheme uses dashes everywhere ("claude-opus-4-7",
// not "claude-opus-4.7"); the catalog ids in trusted-router use dots for
// human-readable versioning. We translate at the boundary.
//
// Update this list when Anthropic releases or deprecates models. Sending
// an unknown id to api.anthropic.com returns a 404 with a "Did you mean..."
// hint that you can paste in here.
var modelIDMap = map[string]string{
	"anthropic/claude-opus-4.7":   "claude-opus-4-7",
	"anthropic/claude-sonnet-4.6": "claude-sonnet-4-6",
	"anthropic/claude-haiku-4.5":  "claude-haiku-4-5",
	"anthropic/claude-3-5-sonnet": "claude-3-5-sonnet-20241022",
	// Original Claude 4.0 GA models: Anthropic serves these ONLY under the
	// dated snapshot id (the undated "claude-opus-4"/"claude-sonnet-4" 404).
	// 4.5-4.8 use undated ids and resolve via the dot->dash fallback; the
	// 4.0s need this explicit map. Verified vs api.anthropic.com/v1/models
	// 2026-06-04.
	"anthropic/claude-opus-4":   "claude-opus-4-20250514",
	"anthropic/claude-sonnet-4": "claude-sonnet-4-20250514",
	"claude-opus-4-7":           "claude-opus-4-7",
	"claude-sonnet-4-6":         "claude-sonnet-4-6",
	"claude-haiku-4-5":          "claude-haiku-4-5",
}

type anthropicClient struct {
	apiKey string
	httpc  *http.Client
}

// newAnthropic constructs the Anthropic-direct client. Used as THE Client
// in single-backend builds (see register_anthropic.go) and as ONE OF the
// available clients in multi-backend builds (see multi.go).
func newAnthropic(boot *qtypes.BootstrapData) *anthropicClient {
	// Route through defaultHTTPClient() so the cloud_aws build picks
	// up the vsock-tunneled transport (api.anthropic.com → vsock-proxy
	// 8003 → upstream). Direct pooledHTTPClient() would use net.Dialer
	// and fail in Nitro with "lookup api.anthropic.com on [::1]:53".
	// Override Timeout to match the streaming default this client used
	// to set inline.
	httpc := defaultHTTPClient()
	httpc.Timeout = defaultStreamingHTTPTimeout
	return &anthropicClient{
		apiKey: strings.TrimSpace(boot.AnthropicAPIKey),
		httpc:  httpc,
	}
}

func (c *anthropicClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if handled, err := invokeBYOKStreaming(ctx, req, body, out, firstOptions(options)); handled {
		return err
	}
	if c.apiKey == "" {
		return fmt.Errorf("llm/anthropic: no api key (set QUILL_ANTHROPIC_SECRET)")
	}
	model := directModelID("anthropic", req.Model, firstOptions(options).UpstreamModel)
	if mapped := mapModelID(model); mapped != "" {
		model = mapped
	}
	if model == "" {
		return fmt.Errorf("llm/anthropic: unmapped model %q", req.Model)
	}
	messages, err := anthropicMessagesWithFetchedImages(ctx, body)
	if err != nil {
		return err
	}

	// Build the Anthropic Messages API body. Same shape as `body` but with
	// the resolved upstream model id and `stream: true`.
	reqBody := struct {
		Model       string                      `json:"model"`
		Messages    []qtypes.AnthropicMessage   `json:"messages"`
		System      string                      `json:"system,omitempty"`
		MaxTokens   int                         `json:"max_tokens"`
		Temperature *float64                    `json:"temperature,omitempty"`
		TopP        *float64                    `json:"top_p,omitempty"`
		Tools       []qtypes.AnthropicTool      `json:"tools,omitempty"`
		ToolChoice  *qtypes.AnthropicToolChoice `json:"tool_choice,omitempty"`
		Stream      bool                        `json:"stream"`
	}{
		Model:       model,
		Messages:    messages,
		System:      body.System,
		MaxTokens: body.MaxTokens,
		// Credits path was sending temperature raw; opus-4.7/4.8 reject it
		// (400 "temperature is deprecated"). Route through the same helper the
		// BYOK path already uses so the omission is consistent across paths.
		Temperature: anthropicTemperature(model, body.Temperature),
		TopP:        body.TopP,
		Tools:       body.Tools,
		ToolChoice:  body.ToolChoice,
		Stream:      true,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("llm/anthropic: marshal body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", anthropicURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersionHeader)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/anthropic: invoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("llm/anthropic: read error body: %w", readErr)
		}
		return fmt.Errorf("llm/upstream: http %d: %s", resp.StatusCode, errBody)
	}

	// Response is native Anthropic SSE bytes. Pump them through to the
	// adapter — no re-emission needed.
	_, err = io.Copy(out, resp.Body)
	return err
}

func mapModelID(quillModel string) string {
	quillModel = strings.TrimSpace(quillModel)
	if mapped, ok := modelIDMap[quillModel]; ok {
		return mapped
	}
	if strings.HasPrefix(quillModel, "anthropic/") {
		return mapModelID(strings.TrimPrefix(quillModel, "anthropic/"))
	}
	// Fall through: maybe the caller already passed a raw Anthropic id like
	// "claude-3-5-sonnet-20241022". Normalize catalog-style dotted Claude
	// names at the boundary because Anthropic's API uses dash-separated
	// version ids.
	if strings.HasPrefix(quillModel, "claude-") {
		return strings.ReplaceAll(quillModel, ".", "-")
	}
	return ""
}
