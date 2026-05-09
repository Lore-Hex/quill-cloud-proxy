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
	// per-request client comes from the attested-and-pinned cache and gets
	// rebuilt automatically after cert rotation. nil for every other
	// provider (which use the static pooled httpc).
	httpcGetter func() (*http.Client, error)
}

// resolveHTTPClient returns the httpc for this request. For most providers
// it's a constant (the boot-time-built pool); for tinfoil it routes through
// the attestation cache.
func (c *openAICompatibleClient) resolveHTTPClient() (*http.Client, error) {
	if c.httpcGetter != nil {
		return c.httpcGetter()
	}
	return c.httpc, nil
}

func newOpenAICompatible(provider string, apiKey string) *openAICompatibleClient {
	provider = normalizeDirectProvider(provider)
	return &openAICompatibleClient{
		provider: provider,
		baseURL:  directBaseURL(provider),
		apiKey:   strings.TrimSpace(apiKey),
		httpc:    defaultHTTPClient(),
	}
}

// newTinfoilAttested mirrors newOpenAICompatible but routes every request
// through the attested, TLS-pinned transport built in tinfoil_attest.go.
// On TLS-pin or attestation-verify failure the request hard-fails — there
// is no fall-through to a plain HTTP client, because that would silently
// defeat the confidential-compute guarantee tinfoil's whole product
// promises. The verify chain runs lazily so a transient Sigstore/GitHub
// hiccup at boot doesn't permanently brick the tinfoil path; a request
// that lands during recovery just pays the verify cost itself.
func newTinfoilAttested(apiKey string) *openAICompatibleClient {
	return &openAICompatibleClient{
		provider:    "tinfoil",
		baseURL:     directBaseURL("tinfoil"),
		apiKey:      strings.TrimSpace(apiKey),
		httpc:       nil, // resolved lazily via tinfoilAttestedHTTPClient
		httpcGetter: tinfoilHTTPClientGetter,
	}
}

// tinfoilHTTPClientGetter wraps tinfoilAttestedHTTPClient so the
// openAICompatibleClient struct stays generic over both the static-pool
// case (every other provider) and the lazy-attested case (tinfoil only).
func tinfoilHTTPClientGetter() (*http.Client, error) {
	return tinfoilAttestedHTTPClient(defaultStreamingHTTPTimeout)
}

func (c *openAICompatibleClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if handled, err := invokeBYOKStreaming(ctx, req, body, out, firstOptions(options)); handled {
		return err
	}
	option := firstOptions(options)
	provider := c.provider
	if option.Provider != "" {
		provider = normalizeDirectProvider(option.Provider)
	}
	httpc, err := c.resolveHTTPClient()
	if err != nil {
		return fmt.Errorf("llm/%s: http client unavailable: %w", c.provider, err)
	}
	return invokeOpenAICompatibleStreamingWithClient(
		ctx,
		httpc,
		provider,
		c.baseURL,
		c.apiKey,
		req,
		body,
		out,
		option.UpstreamModel,
	)
}
