//go:build llm_openrouter

// OpenRouter (ZDR) provider — hand-rolled minimal client.
//
// Why OpenRouter?
//
//	AWS Bedrock and GCP Vertex both gate Claude access behind quota that
//	takes weeks to lift on a new account. OpenRouter's ZDR routing lets us
//	reach Anthropic's models on day zero through a contractual no-retain
//	path (their `provider.data_collection: "deny"` plus `provider.only:
//	["Anthropic"]` collapses the routing pool to Anthropic-direct ZDR).
//
// Trust caveat (also documented on the trust page):
//
//	This path adds OpenRouter as a hop the enclave does NOT cryptographically
//	gate. The OpenRouter API key is released to the enclave through the same
//	KMS-attested bootstrap channel as the Bedrock creds, but OpenRouter
//	itself sees the prompt bytes in transit. This is contractual non-
//	retention, not the verifiable kind. Use Bedrock or Vertex for the
//	strongest property; use OpenRouter for breadth-of-models or quota.
//
// Wire layout:
//
//	The enclave has no direct network egress, so the parent runs a
//	vsock-proxy listening on (CID 3, port 8004) forwarding raw bytes to
//	openrouter.ai:443. We TLS-terminate end-to-end inside the enclave; the
//	parent only pumps encrypted bytes (same model as the Bedrock vsock
//	proxy).
//
// Streaming translation:
//
//	OpenRouter speaks OpenAI Chat Completions SSE; the rest of the Quill
//	pipeline (adapter.TransformStream) consumes Anthropic-native SSE. We
//	do a tiny on-the-fly translation here so the contract with the adapter
//	stays unchanged. Three event types is all the adapter needs:
//	content_block_delta (text), message_delta (stop_reason), message_stop.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	openRouterHost = "openrouter.ai"
	openRouterURL  = "https://openrouter.ai/api/v1/chat/completions"
)

var fallbackOpenRouterHTTPClient = pooledHTTPClient(defaultStreamingHTTPTimeout)

// modelIDMap turns the Quill-public model name into OpenRouter's slug.
// We use the explicit slug (no `:zdr` variant suffix) because we also pass
// `provider.data_collection: "deny"` + `provider.only: ["Anthropic"]` in
// the body — that's the strict ZDR pin and it composes with any model.
var modelIDMap = map[string]string{
	"claude-opus-4-7":             "anthropic/claude-opus-4.7",
	"claude-sonnet-4-6":           "anthropic/claude-sonnet-4.6",
	"claude-haiku-4-5":            "anthropic/claude-haiku-4.5",
	"anthropic/claude-opus-4.7":   "anthropic/claude-opus-4.7",
	"anthropic/claude-3-5-sonnet": "anthropic/claude-3.5-sonnet",
	"openai/gpt-4o-mini":          "openai/gpt-4o-mini",
	"google/gemini-1.5-flash":     "google/gemini-flash-1.5",
	"vertex/gemini-2.5-flash":     "google/gemini-2.5-flash",
}

var defaultAutoModelOrder = []string{
	"anthropic/claude-opus-4.7",
	"anthropic/claude-3-5-sonnet",
	"openai/gpt-4o-mini",
	"google/gemini-1.5-flash",
	"vertex/gemini-2.5-flash",
}

type openRouterClient struct {
	apiKey    string
	httpc     *http.Client
	providers []string // pinned upstream-provider list; ZDR contract holds for any of these
	baseURL   string
}

// defaultProviderPin is "google-vertex" — Anthropic Claude served through
// OpenRouter's Vertex backend with `data_collection: deny` for ZDR. This
// is what we ship by default until our own Vertex quota lifts.
//
// OpenRouter expects the provider slug here, not the display name —
// available slugs (queried from a 404 response):
// "google-vertex", "amazon-bedrock", "anthropic". Title-cased
// "Google Vertex" gives a 404 "No allowed providers are available."
//
// Override at boot via QUILL_OPENROUTER_PROVIDERS=slug1,slug2 (comma-
// separated), e.g. "anthropic" for Anthropic-direct or
// "anthropic,amazon-bedrock,google-vertex" to let OpenRouter pick from
// any of three.
const defaultProviderPin = "google-vertex"

func parseProvidersEnv() []string {
	raw := os.Getenv("QUILL_OPENROUTER_PROVIDERS")
	if strings.TrimSpace(raw) == "" {
		return []string{defaultProviderPin}
	}
	out := make([]string, 0, 4)
	for _, p := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return []string{defaultProviderPin}
	}
	return out
}

// newOpenRouterHTTPClient is provided by openrouter_transport_aws.go (vsock
// tunnel through the parent) or openrouter_transport_gcp.go (direct egress,
// since CSP VMs reach the internet without a proxy).
func New(boot *qtypes.BootstrapData) Client {
	return &openRouterClient{
		apiKey:    boot.OpenRouterAPIKey,
		httpc:     newOpenRouterHTTPClient(boot),
		providers: parseProvidersEnv(),
		baseURL:   openRouterURL,
	}
}

// openRouterRequest is the minimal OpenAI-shape body OpenRouter accepts.
// We pass the Anthropic-shape body in (because that's what the adapter
// pipeline produces); convert the messages array trivially since
// AnthropicMessage and OpenAI ChatMessage are structurally identical.
type openRouterRequest struct {
	Model            string           `json:"model"`
	Messages         []openRouterMsg  `json:"messages"`
	Stream           bool             `json:"stream"`
	MaxTokens        int              `json:"max_tokens,omitempty"`
	Temperature      *float64         `json:"temperature,omitempty"`
	TopP             *float64         `json:"top_p,omitempty"`
	Stop             []string         `json:"stop,omitempty"`
	TopK             *int             `json:"top_k,omitempty"`
	Thinking         any              `json:"thinking,omitempty"`
	Seed             *int             `json:"seed,omitempty"`
	FrequencyPenalty *float64         `json:"frequency_penalty,omitempty"`
	PresencePenalty  *float64         `json:"presence_penalty,omitempty"`
	Provider         *providerRouting `json:"provider,omitempty"`
	Tools            []any            `json:"tools,omitempty"`
	ToolChoice       any              `json:"tool_choice,omitempty"`
}

type openRouterMsg struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

// providerRouting pins OpenRouter's upstream-provider choice + enforces
// ZDR. `data_collection: "deny"` filters to providers that contractually
// don't log; `only` further narrows to a configured list (default
// ["Google Vertex"], overridable via QUILL_OPENROUTER_PROVIDERS).
//
// Trust note: OR's pool for Anthropic Claude includes "Anthropic",
// "Amazon Bedrock", and "Google Vertex" — all of which can be filtered
// to ZDR-compliant. Picking a different element here is operational
// (capacity, region, latency), not a stronger trust property: we're not
// the AWS or GCP account holder via OpenRouter, so the PCR0-attested
// KMS / Workload-Identity gates don't apply on this path.
type providerRouting struct {
	DataCollection    string         `json:"data_collection"`
	Order             []string       `json:"order,omitempty"`
	Only              []string       `json:"only,omitempty"`
	Ignore            []string       `json:"ignore,omitempty"`
	AllowFallbacks    *bool          `json:"allow_fallbacks,omitempty"`
	RequireParameters *bool          `json:"require_parameters,omitempty"`
	Quantizations     []string       `json:"quantizations,omitempty"`
	Sort              any            `json:"sort,omitempty"`
	MaxPrice          map[string]any `json:"max_price,omitempty"`
}

func (c *openRouterClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if handled, err := invokeBYOKStreaming(ctx, req, body, out, firstOptions(options)); handled {
		return err
	}
	candidates, err := routeCandidates(req)
	if err != nil {
		return err
	}
	allowFallbacks := requestAllowsFallbacks(req)
	failures := make([]string, 0, len(candidates))
	for i, candidate := range candidates {
		err := c.invokeOne(ctx, candidate, req, body, out)
		if err == nil {
			return nil
		}
		if !allowFallbacks || i == len(candidates)-1 || !isRetryableUpstream(err) {
			if len(failures) > 0 {
				return fmt.Errorf("%w; previous fallback failures: %s", err, strings.Join(failures, "; "))
			}
			return err
		}
		failures = append(failures, err.Error())
	}
	return fmt.Errorf("llm/openrouter: no route candidates")
}

func (c *openRouterClient) invokeOne(
	ctx context.Context,
	model string,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
) error {
	msgs := make([]openRouterMsg, 0, len(body.Messages)+1)
	if body.System != "" {
		msgs = append(msgs, openRouterMsg{Role: "system", Content: body.System})
	}
	for _, m := range body.Messages {
		msgs = append(msgs, openRouterMsg{Role: m.Role, Content: m.Content})
	}

	reqBody := openRouterRequest{
		Model:            model,
		Messages:         msgs,
		Stream:           true,
		MaxTokens:        body.MaxTokens,
		Temperature:      body.Temperature,
		TopP:             body.TopP,
		Stop:             body.StopSequences,
		TopK:             body.TopK,
		Thinking:         body.Thinking,
		Seed:             req.Seed,
		FrequencyPenalty: req.FrequencyPenalty,
		PresencePenalty:  req.PresencePenalty,
		Provider:         c.providerRouting(req),
		Tools:            req.Tools,
		ToolChoice:       req.ToolChoice,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("llm/openrouter: marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint(), bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	// Nice-to-have attribution headers — OpenRouter shows these in the
	// requesting account's analytics. Neither carries prompt content.
	httpReq.Header.Set("HTTP-Referer", "https://api.quillrouter.com")
	httpReq.Header.Set("X-Title", "TrustedRouter")

	resp, err := c.client().Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/openrouter: invoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		errBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("llm/openrouter: read error body: %w", readErr)
		}
		return &upstreamHTTPError{status: resp.StatusCode, body: string(errBody)}
	}
	return translateOpenAIStreamToAnthropic(resp.Body, out)
}

func (c *openRouterClient) endpoint() string {
	if c.baseURL != "" {
		return c.baseURL
	}
	return openRouterURL
}

func (c *openRouterClient) client() *http.Client {
	if c.httpc != nil {
		return c.httpc
	}
	return fallbackOpenRouterHTTPClient
}

func (c *openRouterClient) providerRouting(req *qtypes.OpenAIChatRequest) *providerRouting {
	routing := &providerRouting{
		DataCollection: "deny",
		Only:           append([]string(nil), c.providers...),
	}
	if req.Provider == nil {
		return routing
	}
	routing.Order = normalizeProviders(req.Provider.Order)
	if len(req.Provider.Only) > 0 {
		routing.Only = normalizeProviders(req.Provider.Only)
	}
	routing.Ignore = normalizeProviders(req.Provider.Ignore)
	routing.AllowFallbacks = req.Provider.AllowFallbacks
	routing.RequireParameters = req.Provider.RequireParameters
	routing.Quantizations = append([]string(nil), req.Provider.Quantizations...)
	routing.Sort = req.Provider.Sort
	routing.MaxPrice = req.Provider.MaxPrice

	// The hosted product guarantee is no prompt retention. If a caller asks
	// OpenRouter to allow data collection, keep the stricter setting.
	if strings.EqualFold(req.Provider.DataCollection, "deny") || req.Provider.DataCollection == "" {
		routing.DataCollection = "deny"
	}
	return routing
}

func routeCandidates(req *qtypes.OpenAIChatRequest) ([]string, error) {
	raw := make([]string, 0, len(req.Models)+len(defaultAutoModelOrder)+1)
	if req.Model != "" {
		raw = appendExpanded(raw, req.Model)
	}
	for _, model := range req.Models {
		raw = appendExpanded(raw, model)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("llm/openrouter: model is required")
	}

	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, modelName := range raw {
		mapped, ok := mapModelID(modelName)
		if !ok {
			return nil, fmt.Errorf("llm/openrouter: unknown model: %s", modelName)
		}
		if !seen[mapped] {
			out = append(out, mapped)
			seen[mapped] = true
		}
	}
	if !requestAllowsFallbacks(req) && len(out) > 1 {
		return out[:1], nil
	}
	return out, nil
}

func appendExpanded(out []string, modelName string) []string {
	switch strings.TrimSpace(modelName) {
	case "", "trustedrouter/auto", "openrouter/auto":
		return append(out, defaultAutoModelOrder...)
	default:
		return append(out, modelName)
	}
}

func mapModelID(modelName string) (string, bool) {
	if mapped, ok := modelIDMap[modelName]; ok {
		return mapped, true
	}
	if strings.Contains(modelName, "/") {
		return modelName, true
	}
	return "", false
}

func requestAllowsFallbacks(req *qtypes.OpenAIChatRequest) bool {
	if req.Provider != nil && req.Provider.AllowFallbacks != nil {
		return *req.Provider.AllowFallbacks
	}
	return true
}

func isRetryableUpstream(err error) bool {
	var httpErr *upstreamHTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	return httpErr.status == http.StatusTooManyRequests || httpErr.status >= 500
}

func normalizeProviders(in []string) []string {
	out := make([]string, 0, len(in))
	for _, provider := range in {
		normalized := normalizeProvider(provider)
		if normalized != "" {
			out = append(out, normalized)
		}
	}
	return out
}

func normalizeProvider(provider string) string {
	slug := strings.ToLower(strings.TrimSpace(provider))
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "_", "-")
	switch slug {
	case "vertex", "vertex-ai", "google-vertex":
		return "google-vertex"
	case "bedrock", "amazon-bedrock":
		return "amazon-bedrock"
	case "mistral", "mistral-ai":
		return "mistral"
	case "openai", "anthropic", "deepseek", "cerebras":
		return slug
	default:
		return slug
	}
}
