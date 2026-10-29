package llm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type openAICompatibleClient struct {
	provider string
	baseURL  string
	apiKey   string
	httpc    *http.Client
	// httpcGetter, when non-nil, is consulted instead of the static httpc
	// field on every InvokeStreaming call. Used by the tinfoil path so the
	// per-request client comes from the attested-and-pinned cache and
	// gets rebuilt automatically after cert rotation. nil for every
	// other provider (which use the static pooled httpc).
	httpcGetter func() (*http.Client, error)
}

func newOpenAICompatible(provider string, apiKey string) *openAICompatibleClient {
	provider = normalizeDirectProvider(provider)
	return newOpenAICompatibleAt(provider, directBaseURL(provider), apiKey)
}

func newOpenAICompatibleAt(provider string, baseURL string, apiKey string) *openAICompatibleClient {
	provider = normalizeDirectProvider(provider)
	httpc := defaultHTTPClient()
	if provider == "hixtube" {
		// Keep the cloud's TLS/egress transport. Full-output requests can take
		// longer than ten minutes, but a stalled stream must still fail promptly.
		httpc.Timeout = hixtubeCompletionTimeout
		httpc.Transport = &progressDeadlineTransport{base: httpc.Transport, timeout: hixtubeProgressTimeout}
	}
	return &openAICompatibleClient{
		provider: provider,
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   strings.TrimSpace(apiKey),
		httpc:    httpc,
	}
}

// newTinfoilAttested mirrors newOpenAICompatible but routes every request
// through the attested, TLS-pinned transport built in tinfoil_attest.go.
// On TLS-pin or attestation-verify failure the request hard-fails — there
// is no fall-through to a plain HTTP client, because that would silently
// defeat the confidential-compute guarantee tinfoil's whole product
// promises.
func newTinfoilAttested(apiKey string) *openAICompatibleClient {
	return &openAICompatibleClient{
		provider:    "tinfoil",
		baseURL:     directBaseURL("tinfoil"),
		apiKey:      strings.TrimSpace(apiKey),
		httpc:       nil, // resolved lazily via tinfoilAttestedHTTPClient
		httpcGetter: tinfoilHTTPClientGetter,
	}
}

func tinfoilHTTPClientGetter() (*http.Client, error) {
	return tinfoilAttestedHTTPClient(defaultStreamingHTTPTimeout)
}

func (c *openAICompatibleClient) resolveHTTPClient() (*http.Client, error) {
	if c.provider == "maple" {
		return nil, fmt.Errorf("llm/maple: ordinary HTTP transport is forbidden")
	}
	if c.httpcGetter != nil {
		return c.httpcGetter()
	}
	return c.httpc, nil
}

func (c *openAICompatibleClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if c.provider == "maple" {
		return invokeMaple(ctx, c.apiKey, req, body, out, firstOptions(options))
	}
	if c.provider == "privatemode" {
		return c.invokePrivatemode(ctx, req, body, out, firstOptions(options))
	}
	if c.provider == "scaledown" {
		return c.invokeScaleDown(ctx, req, out, firstOptions(options))
	}
	option := firstOptions(options)
	if c.provider == "cloudflare-workers-ai" && (option.UpstreamModel == clairicUpstream || (option.UpstreamModel == "" && req != nil && req.Model == clairicModel)) {
		return c.invokeClairic(ctx, req, out, option)
	}
	if handled, err := invokeBYOKStreaming(ctx, req, body, out, firstOptions(options)); handled {
		return err
	}
	provider := c.provider
	if option.Provider != "" {
		provider = normalizeDirectProvider(option.Provider)
	}
	httpc, err := c.resolveHTTPClient()
	if err != nil {
		return fmt.Errorf("llm/%s: http client unavailable: %w", c.provider, err)
	}
	return invokeOpenAICompatibleStreamingWithClientOptions(
		ctx,
		httpc,
		provider,
		c.baseURL,
		c.apiKey,
		req,
		body,
		out,
		option.UpstreamModel,
		openAICompatibleInvocationOptions{
			providerCacheScope: option.ProviderCacheScope,
			waferZDRRequired:   option.WaferZDRRequired,
		},
	)
}
