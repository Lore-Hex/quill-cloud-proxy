package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/privatemode"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var privateModeHTTPClient atomic.Pointer[http.Client]

// ConfigurePrivatemode only accepts the client returned by the in-enclave
// supervisor. A missing/dead proxy disables this provider, never encryption.
func ConfigurePrivatemode(client *http.Client) { privateModeHTTPClient.Store(client) }

func (c *openAICompatibleClient) invokePrivatemode(ctx context.Context, req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest, out io.Writer, option InvokeOptions) error {
	if strings.TrimSpace(option.ProviderAPIKey) != "" {
		return errors.New("llm/privatemode: BYOK is not supported")
	}
	if strings.TrimSpace(c.apiKey) == "" {
		return errors.New("llm/privatemode: credentials unavailable")
	}
	if !privatemode.AllowedModel(option.UpstreamModel) {
		return errors.New("llm/privatemode: model is not release-pinned")
	}
	client := privateModeHTTPClient.Load()
	if client == nil {
		return errors.New("llm/privatemode: attested proxy unavailable")
	}
	return invokeOpenAICompatibleStreamingWithClientOptions(ctx, client, "privatemode", privatemode.BaseURL,
		c.apiKey, req, body, out, option.UpstreamModel, openAICompatibleInvocationOptions{providerCacheScope: option.ProviderCacheScope})
}

// Never substitute an expensive default for an unsupported explicit effort.
// The pinned models all reason; none supports disabling reasoning entirely.
func preparePrivatemodeWire(req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, wire *openAICompatibleRequest, scope string) error {
	invalid := func() error {
		return &upstreamHTTPError{status: http.StatusBadRequest, body: "unsupported Privatemode reasoning setting; GLM supports low/high/max, GPT OSS supports low/medium/high; reasoning cannot be disabled"}
	}
	effort := chatReasoningEffort(req)
	if req != nil {
		if reasoning, ok := req.Reasoning.(map[string]any); ok {
			if enabled, present := reasoning["enabled"].(bool); present && !enabled {
				return invalid()
			}
			if reasoning["max_tokens"] != nil {
				return invalid()
			}
		}
	}
	// Native Anthropic token budgets have no lossless mapping to effort levels.
	if body != nil && body.NativeContent && body.Thinking != nil {
		return invalid()
	}
	if effort != "" && effort != "low" && effort != "high" &&
		!(wire.Model == "gpt-oss-120b" && effort == "medium") &&
		!(strings.HasPrefix(wire.Model, "glm-") && effort == "max") {
		return invalid()
	}
	wire.Thinking, wire.Reasoning = nil, nil
	wire.ReasoningEffort = effort
	// Scope is generated from the authorized workspace, never client input.
	// An absent scope leaves the vendor's fresh-per-request salt in place.
	if scope = strings.TrimSpace(scope); scope != "" {
		digest := sha256.Sum256([]byte("privatemode-cache-v1\x00" + scope))
		wire.CacheSalt = hex.EncodeToString(digest[:])
	}
	return nil
}
