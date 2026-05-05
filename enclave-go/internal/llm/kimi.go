//go:build llm_kimi || llm_multi

// Direct Moonshot AI / Kimi backend. Reuses the shared OpenAI-compatible
// streaming helper in byok.go: same wire shape, just a Quill-managed key
// from BootstrapData.KimiAPIKey instead of a per-user BYOK key.
//
// Wire path:
//   enclave → api.moonshot.ai/v1/chat/completions (TLS terminated at
//   Moonshot, prompts visible to the Moonshot service — same intrinsic
//   property any LLM provider has)
//
// The translateOpenAIStreamToAnthropic helper (see stream_translate.go)
// converts the upstream OpenAI ChatCompletion SSE into native Anthropic
// SSE so the rest of the gateway pipeline keeps its current contract;
// no changes needed in adapter/.
package llm

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type kimiClient struct {
	apiKey string
	httpc  *http.Client
}

// newKimi constructs the Moonshot client. Used as one of the available
// clients in multi-backend builds; in a single-backend llm_kimi build,
// register_kimi.go wires it as THE Client.
func newKimi(boot *qtypes.BootstrapData) *kimiClient {
	return &kimiClient{
		apiKey: strings.TrimSpace(boot.KimiAPIKey),
		httpc:  &http.Client{Timeout: 10 * time.Minute},
	}
}

func (c *kimiClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if handled, err := invokeBYOKStreaming(ctx, req, body, out, firstOptions(options)); handled {
		return err
	}
	return InvokeOpenAICompatibleStreaming(ctx, "kimi", directBaseURL("kimi"), c.apiKey, req, body, out)
}
