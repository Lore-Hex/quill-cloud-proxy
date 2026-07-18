package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var claude5Generation = regexp.MustCompile(`claude-[a-z][a-z0-9]*-5([.-]|$)`)

func firstOptions(options []InvokeOptions) InvokeOptions {
	if len(options) == 0 {
		return InvokeOptions{}
	}
	return options[0]
}

func invokeBYOKStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options InvokeOptions,
) (bool, error) {
	if strings.TrimSpace(options.ProviderAPIKey) == "" {
		return false, nil
	}
	provider := normalizeDirectProvider(options.Provider)
	switch {
	case provider == "anthropic":
		return true, invokeAnthropicBYOKStreaming(ctx, req, body, out, options.ProviderAPIKey, options.UpstreamModel)
	case isOpenAICompatibleBYOKProvider(provider):
		return true, invokeOpenAICompatibleBYOKStreaming(ctx, provider, req, body, out, options.ProviderAPIKey, options.UpstreamModel, options.ProviderCacheScope)
	default:
		return true, fmt.Errorf("llm/byok: unsupported provider %q", options.Provider)
	}
}

func isOpenAICompatibleBYOKProvider(provider string) bool {
	switch provider {
	case "openai", "cerebras", "deepseek", "mistral", "kimi", "gemini", "google-ai-studio", "zai", "together",
		"fireworks", "grok", "novita", "phala", "siliconflow", "tinfoil", "venice",
		"parasail", "lightning", "gmi", "deepinfra", "friendli", "baseten", "thinkingmachines", "wafer",
		"crusoe", "makora", "nebius", "minimax", "xiaomi":
		return true
	default:
		return false
	}
}

type openAICompatibleRequest struct {
	Model           string        `json:"model"`
	Messages        []chatMessage `json:"messages"`
	Stream          bool          `json:"stream"`
	UserCacheSecret string        `json:"user_cache_secret,omitempty"`
	// max_tokens vs max_completion_tokens: OpenAI's gpt-5.x family
	// (gpt-5, gpt-5.1, ..., gpt-5.4, gpt-5.4-mini, gpt-5.4-nano,
	// gpt-5.5, ...) REQUIRES `max_completion_tokens` and returns
	// 400 `unsupported_parameter: max_tokens` if you send the older
	// name. Pre-5.x models still accept `max_tokens`. Some other
	// openai-compatible providers (zai, kimi, novita, etc.) only
	// know `max_tokens`. So this client emits ONE or the OTHER per
	// request — see buildOpenAICompatibleRequest below.
	MaxTokens           int                `json:"max_tokens,omitempty"`
	MaxCompletionTokens int                `json:"max_completion_tokens,omitempty"`
	Temperature         *float64           `json:"temperature,omitempty"`
	TopP                *float64           `json:"top_p,omitempty"`
	TopK                *int               `json:"top_k,omitempty"`
	Seed                *int               `json:"seed,omitempty"`
	FrequencyPenalty    *float64           `json:"frequency_penalty,omitempty"`
	PresencePenalty     *float64           `json:"presence_penalty,omitempty"`
	LogitBias           map[string]float64 `json:"logit_bias,omitempty"`
	Stop                any                `json:"stop,omitempty"`
	ResponseFormat      any                `json:"response_format,omitempty"`
	Tools               []any              `json:"tools,omitempty"`
	ToolChoice          any                `json:"tool_choice,omitempty"`
	ParallelToolCalls   *bool              `json:"parallel_tool_calls,omitempty"`
	Thinking            any                `json:"thinking,omitempty"`
	Reasoning           any                `json:"reasoning,omitempty"`
	ReasoningEffort     string             `json:"reasoning_effort,omitempty"`
	// StreamOptions asks the upstream for the final usage-bearing chunk
	// (stream_options.include_usage). Always sent: real token counts feed
	// settlement (replacing chars/4 estimates that miscounted reasoning
	// models) and the client-facing include_usage chunk. Standard across
	// OpenAI, vLLM, and SGLang-backed providers; verified per provider by
	// the post-deploy smoke matrix.
	StreamOptions *openAICompatibleStreamOptions `json:"stream_options,omitempty"`
}

type openAICompatibleStreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// requiresMaxCompletionTokens returns true for OpenAI models that
// reject the legacy `max_tokens` parameter. Currently the gpt-5.x
// family (and the o-series via the same Responses-style param naming
// — though we mostly route those through the Responses API). Match
// is intentionally loose: any model id that starts with `gpt-5`,
// `o1`, `o3`, or `o4` (with optional vendor prefix) flips the
// parameter name. Add more as OpenAI ships new families.
func requiresMaxCompletionTokens(provider, modelID string) bool {
	if provider != "openai" {
		return false
	}
	m := strings.ToLower(modelID)
	// Strip vendor prefix if present (e.g. "openai/gpt-5.4-mini" -> "gpt-5.4-mini").
	if i := strings.Index(m, "/"); i >= 0 {
		m = m[i+1:]
	}
	for _, prefix := range []string{"gpt-5", "o1", "o3", "o4"} {
		if strings.HasPrefix(m, prefix) {
			return true
		}
	}
	return false
}

type chatMessage struct {
	Role       string           `json:"role"`
	Content    any              `json:"content"`
	ToolCalls  []map[string]any `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

func invokeOpenAICompatibleBYOKStreaming(
	ctx context.Context,
	provider string,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	apiKey string,
	upstreamModel string,
	providerCacheScope string,
) error {
	return InvokeOpenAICompatibleStreaming(ctx, provider, directBaseURL(provider), apiKey, req, body, out, upstreamModel, providerCacheScope)
}

// InvokeOpenAICompatibleStreaming is the shared OpenAI-compatible upstream
// streaming helper used by both the BYOK path (per-user API key) and the
// credit-flow path (Quill-managed API key fetched from Secret Manager).
// Reads upstream OpenAI ChatCompletion SSE chunks, translates to native
// Anthropic SSE so the rest of the gateway pipeline keeps its current
// Anthropic-shaped contract.
//
// Provider must be the normalized slug ("kimi", "zai", "openai", etc.).
// baseURL should not have a trailing slash; "/chat/completions" is
// appended. apiKey is sent as a Bearer token.
func InvokeOpenAICompatibleStreaming(
	ctx context.Context,
	provider, baseURL, apiKey string,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	upstreamModel string,
	providerCacheScopes ...string,
) error {
	providerCacheScope := ""
	if len(providerCacheScopes) > 0 {
		providerCacheScope = providerCacheScopes[0]
	}
	return invokeOpenAICompatibleStreamingWithClient(
		ctx,
		defaultHTTPClient(),
		provider,
		baseURL,
		apiKey,
		req,
		body,
		out,
		upstreamModel,
		providerCacheScope,
	)
}

func invokeOpenAICompatibleStreamingWithClient(
	ctx context.Context,
	httpc *http.Client,
	provider, baseURL, apiKey string,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	upstreamModel string,
	providerCacheScopes ...string,
) error {
	providerCacheScope := ""
	if len(providerCacheScopes) > 0 {
		providerCacheScope = providerCacheScopes[0]
	}
	if strings.TrimSpace(apiKey) == "" {
		return fmt.Errorf("llm/%s: missing api key", provider)
	}
	if strings.TrimSpace(baseURL) == "" {
		return fmt.Errorf("llm/%s: missing base URL", provider)
	}
	msgs, err := openAICompatibleMessagesWithFetchedImages(ctx, body)
	if err != nil {
		return err
	}
	upstreamID := directModelID(provider, req.Model, upstreamModel)
	reqBody := buildOpenAICompatibleRequest(provider, upstreamID, req, body, msgs)
	if normalizeDirectProvider(provider) == "tinfoil" {
		reqBody.UserCacheSecret = strings.TrimSpace(providerCacheScope)
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("llm/%s: marshal body: %w", provider, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("User-Agent", "TrustedRouter/1.0")
	if provider == "wafer" && waferModelSupportsZDR(upstreamID) {
		httpReq.Header.Set("Wafer-ZDR", "required")
	}

	if httpc == nil {
		httpc = defaultHTTPClient()
	}
	resp, err := httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/%s: invoke: %w", provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("llm/%s: read error body: %w", provider, readErr)
		}
		return &upstreamHTTPError{status: resp.StatusCode, body: string(errBody)}
	}
	return translateOpenAIStreamToAnthropic(resp.Body, out)
}

func buildOpenAICompatibleRequest(
	provider string,
	upstreamID string,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	msgs []chatMessage,
) openAICompatibleRequest {
	reqBody := openAICompatibleRequest{
		Model:    upstreamID,
		Messages: msgs,
		Stream:   true,
	}
	if body != nil {
		reqBody.Temperature = openAICompatibleTemperature(provider, upstreamID, body.Temperature)
		reqBody.TopP = body.TopP
		reqBody.TopK = body.TopK
		// Most direct providers that expose reasoning use their native
		// `thinking` extension. Meta's Muse endpoint is reached through
		// OpenRouter and accepts OpenRouter's `reasoning` fields instead.
		if provider != "meta" {
			reqBody.Thinking = body.Thinking
		}
		// max_tokens is OPTIONAL on the OpenAI-compatible surface, so only
		// forward a cap the CLIENT actually set. body.MaxTokens always holds a
		// value because the Anthropic/Bedrock wire format requires one — but
		// forwarding that 4096 default here silently truncated reasoning
		// models mid-think (finish_reason=length, sometimes empty content)
		// while the same request sent direct ran to the provider's own
		// model-max default. When the client did set a cap:
		// per-model parameter rename — openai gpt-5.x rejects max_tokens and
		// requires max_completion_tokens; every other openai-compatible
		// provider (and pre-5.x openai models) still wants max_tokens. Emit
		// exactly one of the two (omitempty hides ints == 0).
		if body.MaxTokensExplicit {
			if requiresMaxCompletionTokens(provider, upstreamID) {
				reqBody.MaxCompletionTokens = body.MaxTokens
			} else {
				reqBody.MaxTokens = body.MaxTokens
			}
		}
	}
	if req != nil {
		reqBody.Reasoning = req.Reasoning
		reqBody.ReasoningEffort = req.ReasoningEffort
		reqBody.Tools = req.Tools
		reqBody.ToolChoice = req.ToolChoice
		reqBody.ParallelToolCalls = req.ParallelTools
		reqBody.Seed = req.Seed
		reqBody.FrequencyPenalty = req.FrequencyPenalty
		reqBody.PresencePenalty = req.PresencePenalty
		reqBody.LogitBias = req.LogitBias
		reqBody.Stop = req.Stop
		if len(req.ResponseFormat) > 0 {
			reqBody.ResponseFormat = req.ResponseFormat
		}
		if kimiToolsNeedThinkingDisabled(provider, upstreamID, req.Tools) {
			reqBody.Thinking = map[string]string{"type": "disabled"}
		}
	}
	reqBody.StreamOptions = &openAICompatibleStreamOptions{IncludeUsage: true}
	return reqBody
}

func openAICompatibleTemperature(provider, modelID string, temperature *float64) *float64 {
	if provider == "kimi" {
		model := strings.ToLower(modelID)
		if strings.Contains(model, "kimi-k2.") || strings.Contains(model, "kimi-k3") {
			return nil
		}
	}
	// OpenAI gpt-5.x / o-series reasoning models reject any temperature other
	// than the default (1): forwarding temperature=0 returns
	// `http 400: 'temperature' does not support 0 with this model`. This bit the
	// internal Fusion panel, which set temperature=0 on its gpt-5.5 panelist and
	// got a 400 every round. Omit it for those models (same family that needs
	// max_completion_tokens); the model behaves as if temperature were defaulted.
	if requiresMaxCompletionTokens(provider, modelID) {
		return nil
	}
	return temperature
}

func kimiToolsNeedThinkingDisabled(provider, modelID string, tools []any) bool {
	if provider != "kimi" || len(tools) == 0 {
		return false
	}
	model := strings.ToLower(modelID)
	return strings.Contains(model, "k2.6") || strings.Contains(model, "k2.5")
}

// anthropicUpstreamMessages returns the message list for an
// anthropic-direct request body. Native /v1/messages content passes
// through verbatim — running chatPartFromAny over already-Anthropic
// blocks (tool_result, image sources, cache_control) would mangle them.
func anthropicUpstreamMessages(
	ctx context.Context,
	body *qtypes.AnthropicMessagesRequest,
) ([]qtypes.AnthropicMessage, error) {
	if body.NativeContent {
		return body.Messages, nil
	}
	return anthropicMessagesWithFetchedImages(ctx, body)
}

// anthropicSystemField prefers the raw native system blocks (preserving
// cache_control) and falls back to the flattened string. nil keeps
// `system` off the wire entirely (omitempty only elides nil for `any`).
func anthropicSystemField(body *qtypes.AnthropicMessagesRequest) any {
	if body.SystemRaw != nil {
		return body.SystemRaw
	}
	if body.System != "" {
		return body.System
	}
	return nil
}

func invokeAnthropicBYOKStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	apiKey string,
	upstreamModel string,
) error {
	return invokeAnthropicBYOKStreamingWithClient(ctx, defaultHTTPClient(), req, body, out, apiKey, upstreamModel)
}

// anthropicWireRequest is an explicit provider projection. Router-only fields
// live on the inbound request types and cannot enter this wire shape by future
// struct-tag additions.
type anthropicWireRequest struct {
	Model         string                      `json:"model"`
	Messages      []qtypes.AnthropicMessage   `json:"messages"`
	System        any                         `json:"system,omitempty"`
	MaxTokens     int                         `json:"max_tokens"`
	Temperature   *float64                    `json:"temperature,omitempty"`
	TopP          *float64                    `json:"top_p,omitempty"`
	Tools         []qtypes.AnthropicTool      `json:"tools,omitempty"`
	ToolChoice    *qtypes.AnthropicToolChoice `json:"tool_choice,omitempty"`
	StopSequences []string                    `json:"stop_sequences,omitempty"`
	Thinking      any                         `json:"thinking,omitempty"`
	Metadata      map[string]any              `json:"metadata,omitempty"`
	TopK          *int                        `json:"top_k,omitempty"`
	OutputConfig  any                         `json:"output_config,omitempty"`
	Stream        bool                        `json:"stream"`
}

func buildAnthropicWireRequest(
	modelID string,
	messages []qtypes.AnthropicMessage,
	body *qtypes.AnthropicMessagesRequest,
) anthropicWireRequest {
	return anthropicWireRequest{
		Model:         modelID,
		Messages:      messages,
		System:        anthropicSystemField(body),
		MaxTokens:     body.AnthropicDispatchMaxTokens(),
		Temperature:   anthropicTemperature(modelID, body.Temperature),
		TopP:          body.TopP,
		Tools:         body.Tools,
		ToolChoice:    body.ToolChoice,
		StopSequences: body.StopSequences,
		Thinking:      body.Thinking,
		Metadata:      body.Metadata,
		TopK:          body.TopK,
		OutputConfig:  body.OutputConfig,
		Stream:        true,
	}
}

func invokeAnthropicBYOKStreamingWithClient(
	ctx context.Context,
	httpc *http.Client,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	apiKey string,
	upstreamModel string,
) error {
	messages, err := anthropicUpstreamMessages(ctx, body)
	if err != nil {
		return err
	}
	modelID := directModelID("anthropic", req.Model, upstreamModel)
	reqBody := buildAnthropicWireRequest(modelID, messages, body)
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("llm/byok: marshal anthropic body: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	if httpc == nil {
		httpc = defaultHTTPClient()
	}
	resp, err := httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/byok: anthropic invoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("llm/byok: read anthropic error body: %w", readErr)
		}
		return &upstreamHTTPError{status: resp.StatusCode, body: string(errBody)}
	}
	_, err = io.Copy(out, resp.Body)
	return err
}

func anthropicTemperature(modelID string, temperature *float64) *float64 {
	model := strings.ToLower(modelID)
	// Anthropic rejects temperature on Claude 5-generation models. The
	// regexp covers future 5-family members so the next launch doesn't
	// repeat this incident.
	if claude5Generation.MatchString(model) {
		return nil
	}
	if strings.Contains(model, "claude-opus-4-7") || strings.Contains(model, "claude-opus-4-8") {
		return nil
	}
	if temperature != nil && *temperature > 1.0 {
		clamped := 1.0
		return &clamped
	}
	return temperature
}

func openAICompatibleMessagesWithFetchedImages(
	ctx context.Context,
	body *qtypes.AnthropicMessagesRequest,
) ([]chatMessage, error) {
	msgs := make([]chatMessage, 0, len(body.Messages)+1)
	if body.System != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: body.System})
	}
	for _, message := range body.Messages {
		if converted, ok := openAICompatibleToolMessages(message); ok {
			msgs = append(msgs, converted...)
			continue
		}
		content, err := openAICompatibleContentWithFetchedImages(ctx, message.Content)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, chatMessage{Role: message.Role, Content: content})
	}
	return msgs, nil
}

// openAICompatibleToolMessages reverses the Anthropic tool_use/tool_result
// content blocks that adapter.ToAnthropic produced (the request reached us as
// OpenAI /chat/completions, was normalized to Anthropic, and is now headed back
// out to an OpenAI-compatible upstream). Without this, the upstream receives
// Anthropic-shaped {"type":"tool_use"|"tool_result"} blocks it cannot parse, so
// after a tool turn it loses the tool context and returns an empty answer
// (observed with DeepSeek; Kimi happened to tolerate the malformed history).
// Returns (messages, true) when the message carried tool blocks and was
// translated; (nil, false) to fall through to normal content handling.
func openAICompatibleToolMessages(message qtypes.AnthropicMessage) ([]chatMessage, bool) {
	blocks, ok := anthropicContentBlocks(message.Content)
	if !ok {
		return nil, false
	}
	hasTool := false
	for _, block := range blocks {
		switch stringValue(block["type"]) {
		case "tool_use", "tool_result":
			hasTool = true
		}
	}
	if !hasTool {
		return nil, false
	}
	if message.Role == "assistant" {
		var text strings.Builder
		toolCalls := make([]map[string]any, 0, len(blocks))
		for _, block := range blocks {
			switch stringValue(block["type"]) {
			case "text":
				text.WriteString(stringValue(block["text"]))
			case "tool_use":
				toolCalls = append(toolCalls, map[string]any{
					"id":   stringValue(block["id"]),
					"type": "function",
					"function": map[string]any{
						"name":      stringValue(block["name"]),
						"arguments": toolUseArguments(block["input"]),
					},
				})
			}
		}
		// content is "" (not nil) for tool-only turns: matches what DeepSeek's
		// own API accepts and keeps the JSON field present.
		return []chatMessage{{Role: "assistant", Content: text.String(), ToolCalls: toolCalls}}, true
	}
	// A user message carrying tool_result block(s) becomes one role:"tool"
	// message per result (the OpenAI-compatible shape); any stray text becomes a
	// trailing user message.
	out := make([]chatMessage, 0, len(blocks))
	var leftover strings.Builder
	for _, block := range blocks {
		switch stringValue(block["type"]) {
		case "tool_result":
			out = append(out, chatMessage{
				Role:       "tool",
				ToolCallID: stringValue(block["tool_use_id"]),
				Content:    anthropicToolResultText(block["content"]),
			})
		case "text":
			leftover.WriteString(stringValue(block["text"]))
		}
	}
	if strings.TrimSpace(leftover.String()) != "" {
		out = append(out, chatMessage{Role: "user", Content: leftover.String()})
	}
	return out, true
}

// anthropicContentBlocks normalizes an Anthropic message Content into a slice of
// block maps, accepting both []map[string]any (what ToAnthropic emits) and the
// generic []any decoded shape.
func anthropicContentBlocks(content any) ([]map[string]any, bool) {
	switch value := content.(type) {
	case []map[string]any:
		return value, true
	case []any:
		blocks := make([]map[string]any, 0, len(value))
		for _, item := range value {
			block, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			blocks = append(blocks, block)
		}
		return blocks, len(blocks) > 0
	default:
		return nil, false
	}
}

// toolUseArguments renders an Anthropic tool_use input (a decoded object) back
// into the JSON string OpenAI-compatible APIs expect for
// tool_calls[].function.arguments.
func toolUseArguments(input any) string {
	if input == nil {
		return "{}"
	}
	if s, ok := input.(string); ok {
		return s
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

// anthropicToolResultText flattens an Anthropic tool_result content value (a
// string, or a list of text blocks) into the plain string an OpenAI-compatible
// tool message carries.
func anthropicToolResultText(content any) string {
	switch value := content.(type) {
	case string:
		return value
	case []map[string]any:
		var b strings.Builder
		for _, block := range value {
			b.WriteString(stringValue(block["text"]))
		}
		return b.String()
	case []any:
		var b strings.Builder
		for _, item := range value {
			if block, ok := item.(map[string]any); ok {
				b.WriteString(stringValue(block["text"]))
			}
		}
		return b.String()
	case nil:
		return ""
	default:
		if encoded, err := json.Marshal(value); err == nil {
			return string(encoded)
		}
		return ""
	}
}

func openAICompatibleContentWithFetchedImages(ctx context.Context, content any) (any, error) {
	switch value := content.(type) {
	case string:
		return value, nil
	case []qtypes.ChatContentPart:
		return openAICompatiblePartsWithFetchedImages(ctx, value)
	case []any:
		parts := make([]qtypes.ChatContentPart, 0, len(value))
		for _, item := range value {
			part, err := chatPartFromAny(item)
			if err != nil {
				return nil, err
			}
			parts = append(parts, part)
		}
		return openAICompatiblePartsWithFetchedImages(ctx, parts)
	default:
		return content, nil
	}
}

func openAICompatiblePartsWithFetchedImages(
	ctx context.Context,
	parts []qtypes.ChatContentPart,
) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(parts))
	for _, part := range parts {
		switch part.Type {
		case "", "text", "input_text":
			if strings.TrimSpace(part.Text) != "" {
				out = append(out, map[string]any{"type": "text", "text": part.Text})
			}
		case "image_url", "input_image":
			if part.ImageURL == nil || strings.TrimSpace(part.ImageURL.URL) == "" {
				return nil, fmt.Errorf("llm/image: image_url is required")
			}
			dataURL, err := openAICompatibleImageDataURL(ctx, part.ImageURL.URL)
			if err != nil {
				return nil, err
			}
			imageURL := map[string]any{"url": dataURL}
			if strings.TrimSpace(part.ImageURL.Detail) != "" {
				imageURL["detail"] = part.ImageURL.Detail
			}
			out = append(out, map[string]any{
				"type":      "image_url",
				"image_url": imageURL,
			})
		default:
			return nil, fmt.Errorf("llm/image: unsupported content part %q", part.Type)
		}
	}
	return out, nil
}

func openAICompatibleImageDataURL(ctx context.Context, raw string) (string, error) {
	mediaType, data, err := loadImageBytes(ctx, raw)
	if err != nil {
		return "", err
	}
	normalizedType, normalizedData, err := normalizeImageBytes(mediaType, data)
	if err != nil {
		return "", err
	}
	return "data:" + normalizedType + ";base64," + base64.StdEncoding.EncodeToString(normalizedData), nil
}

func directBaseURL(provider string) string {
	switch provider {
	case "openai":
		return "https://api.openai.com/v1"
	case "meta":
		// Meta Muse Spark is currently served through OpenRouter. The
		// control-plane provider label is deliberately "Meta via OpenRouter".
		return "https://openrouter.ai/api/v1"
	case "cerebras":
		return "https://api.cerebras.ai/v1"
	case "deepseek":
		return "https://api.deepseek.com"
	case "mistral":
		return "https://api.mistral.ai/v1"
	case "kimi":
		return "https://api.moonshot.ai/v1"
	case "gemini", "google-ai-studio":
		return "https://generativelanguage.googleapis.com/v1beta/openai"
	case "zai":
		// Z.AI's open OpenAI-compatible endpoint. The legacy
		// open.bigmodel.cn host serves the same surface but is being
		// deprecated; new keys are issued under api.z.ai.
		return "https://api.z.ai/api/paas/v4"
	case "together":
		// Together AI hosts the open-weight catalog (Llama, DeepSeek
		// incl. DeepSeek-OCR, Qwen, Mixtral) plus image gen + embeddings.
		// OpenAI-compatible chat completions at api.together.xyz/v1.
		return "https://api.together.xyz/v1"
	case "fireworks":
		// Fireworks AI serverless inference. OpenAI-compatible at the
		// non-standard /inference/v1 base path.
		return "https://api.fireworks.ai/inference/v1"
	case "voyage":
		// Voyage AI retrieval embeddings. OpenAI-shaped /v1/embeddings.
		return "https://api.voyageai.com/v1"
	case "xiaomi":
		// Xiaomi MiMo (MiMo-V2 / V2.5 family). OpenAI-compatible chat
		// completions at api.xiaomimimo.com/v1 (Bearer auth).
		return "https://api.xiaomimimo.com/v1"
	case "grok":
		// xAI Grok. OpenAI-compatible chat completions.
		return "https://api.x.ai/v1"
	case "novita":
		// Novita AI multi-vendor serverless inference.
		return "https://api.novita.ai/v3/openai"
	case "phala":
		// Phala confidential AI — Intel TDX + NVIDIA CC TEEs.
		// `api.redpill.ai` is what Phala's official docs use (Yan @
		// Phala confirmed 2026-05-13 that `api.red-pill.ai` is an
		// alias that also works; we normalized on the no-hyphen form
		// across every reference in the codebase so the AWS vsock-
		// proxy host filter, parent bootstrap, and scraper URL all
		// agree).
		//
		// We route exclusively to the GPU-TEE-attested tier via the
		// `phala/<bare>` model id form (see phalaModelMap below).
		// The upstream-pass-through tier uses a different (redpill)
		// key TR doesn't have.
		return "https://api.redpill.ai/v1"
	case "siliconflow":
		// SiliconFlow Chinese serverless inference (200+ open-weight
		// models). The .com endpoint is the international one; .cn is
		// the China-only mirror.
		return "https://api.siliconflow.com/v1"
	case "tinfoil":
		// Tinfoil TEE-attested confidential inference. The base URL is
		// served from inside an Intel SGX/TDX enclave with attestation
		// document fetchable via the same hostname.
		return "https://inference.tinfoil.sh/v1"
	case "venice":
		// Venice.AI privacy-focused gateway. /api/v1 base path quirk.
		return "https://api.venice.ai/api/v1"
	case "parasail":
		// Parasail serverless inference. OpenAI-compatible.
		return "https://api.parasail.io/v1"
	case "lightning":
		// Lightning AI hosted inference. OpenAI-compatible at the
		// non-standard `/api/v1` path.
		return "https://lightning.ai/api/v1"
	case "gmi":
		// GMI Cloud confidential-GPU inference. OpenAI-compatible.
		return "https://api.gmi-serving.com/v1"
	case "deepinfra":
		// DeepInfra OpenAI-compatible chat completions. Note the
		// `/v1/openai` path (not `/v1`) — DeepInfra namespaces the
		// OpenAI-shape endpoints separately from their native /v1.
		return "https://api.deepinfra.com/v1/openai"
	case "friendli":
		// FriendliAI serverless Model API. OpenAI-compatible /v1 surface
		// under the non-standard /serverless prefix.
		return "https://api.friendli.ai/serverless/v1"
	case "baseten":
		// Baseten Model APIs. OpenAI-compatible chat completions.
		return "https://inference.baseten.co/v1"
	case "thinkingmachines":
		return "https://tinker.thinkingmachines.dev/services/tinker-prod/oai/api/v1"
	case "wafer":
		// Wafer serverless API. OpenAI-compatible chat completions; requests
		// include Wafer-ZDR: required in invokeOpenAICompatibleStreamingWithClient.
		return "https://pass.wafer.ai/v1"
	case "crusoe":
		// Crusoe Managed Inference. OpenAI-compatible chat completions.
		return "https://api.inference.crusoecloud.com/v1"
	case "makora":
		// Makora Inference. OpenAI-compatible chat completions.
		return "https://inference.makora.com/v1"
	case "nebius":
		// Nebius Token Factory OpenAI-compatible shared inference.
		return "https://api.tokenfactory.nebius.com/v1"
	case "minimax":
		// MiniMax first-party international endpoint. The minimaxi.com
		// host is for China-region keys; this project key is scoped to
		// the international api.minimax.io endpoint.
		return "https://api.minimax.io/v1"
	default:
		return ""
	}
}

func directModelID(provider, model, upstreamModel string) string {
	model = stripOpenRouterModelVariant(model)
	upstreamModel = stripOpenRouterModelVariant(strings.TrimSpace(upstreamModel))
	resolved := model
	// Provider-specific overrides (consulted first). Together hosts
	// open-weight models under their own catalog naming
	// (`Llama-3.3-70B-Instruct-Turbo` etc.) rather than the
	// OpenRouter-canonical lowercase. Without this, every Together-
	// routed request 404s. Maintained as a static table because
	// runtime discovery would mean an extra Together API call at
	// boot — net more code in the auditable enclave surface.
	// Per-provider native-id overrides (consulted first). Each
	// second-source provider — Together, Lightning, GMI, DeepInfra,
	// Parasail, Tinfoil — hosts upstream-author models under its own
	// catalog naming (e.g. `Llama-3.3-70B-Instruct-Turbo` on Together,
	// `lightning-ai/gemma-4-31B-it` on Lightning, `kimi-k2-6` on
	// Tinfoil). Without an explicit map, the generic fall-through
	// below strips the OR-canonical author prefix and ships a bare
	// model id that 404s on the provider's API. The per-provider
	// maps are kept in lock-step with the pricing scrapers at
	// `quill-router/scripts/pricing/providers/<slug>.py`, which are
	// the source of truth for which native ids actually exist today.
	if perProvider, ok := providerNativeModelMaps[provider]; ok {
		// These maps are keyed by the OR-canonical (lowercase) model id.
		// The control plane sends the canonical id in `model` and the
		// provider-native catalog id in `upstreamModel` — e.g. Together:
		// model="moonshotai/kimi-k2.6", upstreamModel="moonshotai/Kimi-K2.6".
		// Try the canonical `model` FIRST: a mixed-case upstreamModel
		// ("…/Kimi-K2.6") misses the lowercase map key and would fall
		// through to the author-strip fallback below, which ships a bare
		// "Kimi-K2.6" that Together 404s ("Unable to access model …").
		for _, key := range []string{model, upstreamModel} {
			if key == "" {
				continue
			}
			if mapped, ok := perProvider[stripOpenRouterModelVariant(key)]; ok {
				return mapped
			}
		}
	}
	if providerPreservesAuthorModelID(provider) {
		key := upstreamModel
		if key == "" {
			key = model
		}
		if key != "" {
			return stripOpenRouterModelVariant(key)
		}
	}
	if upstreamModel != "" {
		if mapped, ok := directModelMap[upstreamModel]; ok {
			return stripOpenRouterModelVariant(mapped)
		}
		prefix := provider + "/"
		if strings.HasPrefix(upstreamModel, prefix) {
			resolved = strings.TrimPrefix(upstreamModel, prefix)
			if mapped, ok := directModelMap[resolved]; ok {
				return stripOpenRouterModelVariant(mapped)
			}
			return stripOpenRouterModelVariant(resolved)
		}
		if idx := strings.Index(upstreamModel, "/"); idx >= 0 && idx+1 < len(upstreamModel) {
			resolved = upstreamModel[idx+1:]
			if mapped, ok := directModelMap[resolved]; ok {
				return stripOpenRouterModelVariant(mapped)
			}
			return stripOpenRouterModelVariant(resolved)
		}
		return stripOpenRouterModelVariant(upstreamModel)
	}
	if mapped, ok := directModelMap[model]; ok {
		return stripOpenRouterModelVariant(mapped)
	}
	prefix := provider + "/"
	if strings.HasPrefix(model, prefix) {
		resolved = strings.TrimPrefix(model, prefix)
		return stripOpenRouterModelVariant(resolved)
	}
	if idx := strings.Index(model, "/"); idx >= 0 && idx+1 < len(model) {
		resolved = model[idx+1:]
		return stripOpenRouterModelVariant(resolved)
	}
	return stripOpenRouterModelVariant(resolved)
}

func providerPreservesAuthorModelID(provider string) bool {
	switch provider {
	case "meta", "novita", "nebius", "fireworks":
		return true
	default:
		return false
	}
}

func stripOpenRouterModelVariant(model string) string {
	idx := strings.LastIndex(model, ":")
	if idx < 0 || idx+1 == len(model) {
		return model
	}
	switch strings.ToLower(model[idx+1:]) {
	case "free", "floor", "nitro", "extended", "online":
		return model[:idx]
	default:
		return model
	}
}

// togetherModelMap translates the OpenRouter-canonical model id (what
// the TR control plane sends in the request body) to Together's own
// catalog id. Built once by querying Together's /v1/models against the
// set of Together-served models in src/trusted_router/data/openrouter_snapshot.json
// and refreshed by hand when new Together-hosted models are added.
//
// Anything Together-routed and not in this map falls through to the
// global directModelMap and then to the raw model id — which will 404
// if Together's catalog uses different casing/naming. Backfill on
// demand.
// providerNativeModelMaps is the per-provider OR-canonical →
// provider-native lookup consulted by `directModelID`. Add a new
// provider here when its scraper at
// `quill-router/scripts/pricing/providers/<slug>.py` introduces a
// `_NATIVE_TO_OR_ID` map (i.e. when native ids diverge from OR
// canonical for that provider). Providers absent from this table
// fall through to the generic strip-author logic — fine for any
// upstream whose API accepts the OR-canonical id verbatim.
var providerNativeModelMaps = map[string]map[string]string{
	"together":         togetherModelMap,
	"lightning":        lightningModelMap,
	"parasail":         parasailModelMap,
	"deepinfra":        deepinfraModelMap,
	"gmi":              gmiModelMap,
	"tinfoil":          tinfoilModelMap,
	"novita":           novitaModelMap,
	"phala":            phalaModelMap,
	"venice":           veniceModelMap,
	"friendli":         friendliModelMap,
	"baseten":          basetenModelMap,
	"thinkingmachines": thinkingMachinesModelMap,
	"wafer":            waferModelMap,
	"crusoe":           crusoeModelMap,
	"makora":           makoraModelMap,
	"minimax":          minimaxModelMap,
	"siliconflow":      siliconflowModelMap,
	"zai":              zaiModelMap,
}

// siliconflowModelMap translates OR-canonical → SiliconFlow's native catalog
// ids. SiliconFlow serves the models verbatim but under mixed-case,
// different-author ids (verified against api.siliconflow.com/v1/models
// 2026-06-04): deepseek-ai/* not deepseek/*, zai-org/* not z-ai/*, and
// title-cased model names. Without this, directModelID's strip-author
// fallback ships a bare lowercase id and SiliconFlow 4xxs "Model does not
// exist", which is why every SiliconFlow route was 502ing through the gateway.
var siliconflowModelMap = map[string]string{
	"deepseek/deepseek-v4-flash":    "deepseek-ai/DeepSeek-V4-Flash",
	"deepseek/deepseek-v4-pro":      "deepseek-ai/DeepSeek-V4-Pro",
	"minimax/minimax-m3":            "MiniMaxAI/MiniMax-M3",
	"tencent/hunyuan-a13b-instruct": "tencent/Hunyuan-A13B-Instruct",
	"tencent/hy3-preview":           "tencent/Hy3-preview",
	"z-ai/glm-5":                    "zai-org/GLM-5",
	"z-ai/glm-5.2":                  "zai-org/GLM-5.2",
	"z-ai/glm-5v-turbo":             "zai-org/GLM-5V-Turbo",
}

// zaiModelMap overrides the global directModelMap for zai-direct. zai's API
// (api.z.ai) only accepts the BARE model id ("glm-4.7"); glm-4.5/4.6/5/5.2 already
// work via the generic strip-author fallback, but glm-4.7 has an entry in the
// global directModelMap ("z-ai/glm-4.7" -> "zai-glm-4.7") that other providers
// (e.g. venice) rely on. Override it here for zai only — verified against
// api.z.ai/api/paas/v4 2026-06-04 (bare "glm-4.7" OK; "zai-glm-4.7" =>
// "Unknown Model"). Leaving the global map untouched keeps venice et al. intact.
var zaiModelMap = map[string]string{
	"z-ai/glm-4.7": "glm-4.7",
	"z-ai/glm-5.2": "glm-5.2",
}

var minimaxModelMap = map[string]string{
	"minimax/minimax-m2.7":           "MiniMax-M2.7",
	"minimax/minimax-m2.7-highspeed": "MiniMax-M2.7-highspeed",
	"minimax/minimax-m2.5":           "MiniMax-M2.5",
	"minimax/minimax-m2.5-highspeed": "MiniMax-M2.5-highspeed",
	"minimax/minimax-m2.1":           "MiniMax-M2.1",
	"minimax/minimax-m2.1-highspeed": "MiniMax-M2.1-highspeed",
	"minimax/minimax-m2":             "MiniMax-M2",
}

// togetherModelMap translates OR-canonical model id → Together's own
// catalog id. Together serves open-weight models under their own
// naming (`Llama-3.3-70B-Instruct-Turbo`, `Qwen2.5-7B-Instruct-Turbo`,
// etc.). Kept in lock-step with
// `quill-router/scripts/pricing/providers/together.py`.
var togetherModelMap = map[string]string{
	"deepcogito/cogito-v2.1-671b":       "deepcogito/cogito-v2-1-671b",
	"deepseek/deepseek-v3":              "deepseek-ai/DeepSeek-V3",
	"deepseek/deepseek-v3-ocr":          "deepseek-ai/DeepSeek-V3-OCR",
	"deepseek/deepseek-v4-pro":          "deepseek-ai/DeepSeek-V4-Pro",
	"google/gemma-3n-e4b-it":            "google/gemma-3n-E4B-it",
	"google/gemma-4-31b-it":             "google/gemma-4-31B-it",
	"liquid/lfm-2-24b-a2b":              "LiquidAI/LFM2-24B-A2B",
	"meta-llama/llama-3-8b-chat":        "meta-llama/Llama-3-8b-chat-hf",
	"meta-llama/llama-3-8b-instruct":    "meta-llama/Meta-Llama-3-8B-Instruct-Lite",
	"meta-llama/llama-3.1-8b-instruct":  "meta-llama/Llama-3.1-8B-Instruct-Turbo",
	"meta-llama/llama-3.1-70b-instruct": "meta-llama/Llama-3.1-70B-Instruct-Turbo",
	"meta-llama/llama-3.3-70b-instruct": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
	"meta-llama/llama-guard-4-12b":      "meta-llama/Llama-Guard-4-12B",
	"minimax/minimax-m2.7":              "MiniMaxAI/MiniMax-M2.7",
	"mistralai/mixtral-8x7b-instruct":   "mistralai/Mixtral-8x7B-Instruct-v0.1",
	"moonshotai/kimi-k2-instruct":       "moonshotai/Kimi-K2-Instruct",
	"moonshotai/kimi-k2.5":              "moonshotai/Kimi-K2.5",
	"moonshotai/kimi-k2.6":              "moonshotai/Kimi-K2.6",
	"qwen/qwen-2.5-7b-instruct":         "Qwen/Qwen2.5-7B-Instruct-Turbo",
	"qwen/qwen-2.5-72b-instruct":        "Qwen/Qwen2.5-72B-Instruct-Turbo",
	"qwen/qwen3-coder":                  "Qwen/Qwen3-Coder-Next-FP8",
	"qwen/qwen3-coder-next":             "Qwen/Qwen3-Coder-Next-FP8",
	"qwen/qwen3.5-397b-a17b":            "Qwen/Qwen3.5-397B-A17B",
	"qwen/qwen3.5-9b":                   "Qwen/Qwen3.5-9B",
	"z-ai/glm-5":                        "zai-org/GLM-5",
	"z-ai/glm-5.1":                      "zai-org/GLM-5.1",
	"z-ai/glm-5.2":                      "zai-org/GLM-5.2",
}

// lightningModelMap maps OR-canonical → Lightning AI native.
// Lightning serves models under a `lightning-ai/...` author prefix
// (regardless of upstream author) and preserves upstream caps
// (`31B`, `26B-A4B`). Source:
// `quill-router/scripts/pricing/providers/lightning.py`.
var lightningModelMap = map[string]string{
	"google/gemma-4-31b-it":             "lightning-ai/gemma-4-31B-it",
	"google/gemma-4-26b-a4b-it":         "lightning-ai/gemma-4-26B-A4B-it",
	"meta-llama/llama-3.3-70b-instruct": "lightning-ai/llama-3.3-70b",
	"deepseek/deepseek-v3.1":            "lightning-ai/DeepSeek-V3.1",
}

// parasailModelMap maps OR-canonical → Parasail native. Parasail's
// /v1/models exposes BOTH a `parasail-*` slug AND the upstream-
// author form for each model; we always pick the `parasail-*`
// slug because (a) it pins billing to Parasail's own tier and
// (b) it's case-stable (the upstream-author form Parasail accepts
// is mixed-case like `meta-llama/Llama-3.3-70B-Instruct`, which
// doesn't match our lowercase OR canonical and would still need
// translation).
//
// Source of truth: live probe of https://api.parasail.io/v1/models
// on 2026-05-12 + dashboard pricing pasted by operator. Kept in
// lock-step with `quill-router/scripts/pricing/providers/parasail.py`.
// When a model is added there, mirror the entry here.
var parasailModelMap = map[string]string{
	// gemma
	"google/gemma-4-31b-it":     "parasail-gemma-4-31b-it",
	"google/gemma-4-26b-a4b-it": "parasail-gemma-4-26b-a4b-it",
	"google/gemma-3-27b-it":     "parasail-gemma3-27b-it",
	// llama
	"meta-llama/llama-3.3-70b-instruct": "parasail-llama-33-70b-fp8",
	"meta-llama/llama-4-maverick":       "parasail-llama-4-maverick-instruct-fp8",
	// qwen
	"qwen/qwen2.5-vl-72b-instruct":     "parasail-qwen25-vl-72b-instruct",
	"qwen/qwen3-vl-235b-a22b-instruct": "parasail-qwen3-vl-235b-a22b-instruct",
	"qwen/qwen3-vl-8b-instruct":        "parasail-qwen3vl-8b-instruct",
	"qwen/qwen3-235b-a22b-2507":        "parasail-qwen3-235b-a22b-instruct-2507",
	"qwen/qwen3-coder-next":            "parasail-qwen3-coder-next",
	"qwen/qwen3.5-397b-a17b":           "parasail-qwen35-397b-a17b",
	"qwen/qwen3.5-35b-a3b":             "parasail-qwen3p5-35b-a3b",
	"qwen/qwen3.6-35b-a3b":             "parasail-qwen3p6-35b-a3b",
	"qwen/qwen3-next-80b-a3b-instruct": "parasail-qwen-3-next-80b-instruct",
	// deepseek
	"deepseek/deepseek-v3.2":     "parasail-deepseek-v32",
	"deepseek/deepseek-v4-flash": "parasail-deepseek-v4-flash",
	"deepseek/deepseek-v4-pro":   "parasail-deepseek-v4-pro",
	// z-ai / glm
	"z-ai/glm-5":   "parasail-glm-5",
	"z-ai/glm-5.1": "parasail-glm-51",
	"z-ai/glm-5.2": "parasail-glm-52",
	"z-ai/glm-4.7": "parasail-glm47",
	// moonshot
	"moonshotai/kimi-k2.5": "parasail-kimi-k25",
	"moonshotai/kimi-k2.6": "parasail-kimi-k26",
	// minimax
	"minimax/minimax-m2.5": "parasail-minimax-m25",
	// gpt-oss
	"openai/gpt-oss-120b": "parasail-gpt-oss-120b",
	"openai/gpt-oss-20b":  "parasail-gpt-oss-20b",
	// mistral
	"mistralai/mistral-small-3.2-24b-instruct": "parasail-mistral-small-32-24b",
	// thedrummer / arcee / stepfun / bytedance
	"thedrummer/cydonia-24b-v4.1":     "parasail-cydonia-24-v41",
	"thedrummer/skyfall-36b-v2":       "parasail-skyfall-36b-v2-fp8",
	"stepfun/step-3.5-flash":          "parasail-stepfun35-flash",
	"arcee-ai/trinity-large-thinking": "parasail-trinity-large-thinking",
	"bytedance/ui-tars-1.5-7b":        "parasail-ui-tars-1p5-7b",
}

// deepinfraModelMap maps OR-canonical → DeepInfra native. DeepInfra
// keeps the upstream-author path but capitalizes model-size suffixes
// (`Gemma-4-31B`, `Llama-3.3-70B`) and re-prefixes DeepSeek/Qwen
// under their own org names (`deepseek-ai/`, `Qwen/`). Source:
// `quill-router/scripts/pricing/providers/deepinfra.py`.
var deepinfraModelMap = map[string]string{
	"google/gemma-4-31b-it":             "google/gemma-4-31B-it",
	"google/gemma-4-26b-a4b-it":         "google/gemma-4-26B-A4B-it",
	"google/gemma-3-27b-it":             "google/gemma-3-27b-it",
	"google/gemma-3-12b-it":             "google/gemma-3-12b-it",
	"google/gemma-3-4b-it":              "google/gemma-3-4b-it",
	"meta-llama/llama-3.1-70b-instruct": "meta-llama/Meta-Llama-3.1-70B-Instruct",
	"meta-llama/llama-3.3-70b-instruct": "meta-llama/Llama-3.3-70B-Instruct",
	"deepseek/deepseek-v3.1":            "deepseek-ai/DeepSeek-V3.1",
	"qwen/qwen3.5-27b":                  "Qwen/Qwen3.5-27B",
	"z-ai/glm-5.2":                      "zai-org/GLM-5.2",
}

// gmiModelMap maps OR-canonical → GMI Cloud native. Two patterns:
// (a) gemma-4 / OpenAI / Anthropic models keep the full
// `<author>/<model>` path verbatim, but the generic
// `directModelID` fall-through would strip the author prefix
// down to a bare slug and 404. (b) DeepSeek and z-ai are
// re-prefixed under their org names (`deepseek-ai/`, `zai-org/`).
// Source: `quill-router/scripts/pricing/providers/gmi.py`.
var gmiModelMap = map[string]string{
	"google/gemma-4-31b-it":     "google/gemma-4-31b-it",
	"google/gemma-4-26b-a4b-it": "google/gemma-4-26b-a4b-it",
	"deepseek/deepseek-v4-pro":  "deepseek-ai/DeepSeek-V4-Pro",
	"deepseek/deepseek-v3.1":    "deepseek-ai/DeepSeek-V3.1",
	"z-ai/glm-5":                "zai-org/GLM-5-FP8",
	"z-ai/glm-5.1":              "zai-org/GLM-5.1-FP8",
	"z-ai/glm-5.2":              "zai-org/GLM-5.2-FP8",
	"anthropic/claude-opus-4.7": "anthropic/claude-opus-4.7",
	"openai/gpt-5.4-nano":       "openai/gpt-5.4-nano",
	"openai/gpt-5.5":            "openai/gpt-5.5",
}

// novitaModelMap maps OR-canonical → Novita native. Novita's live
// /openai/v1/models endpoint uses full author-prefixed ids
// (`moonshotai/kimi-k2.6`, `deepseek/deepseek-v4-flash`, etc.).
// `providerPreservesAuthorModelID("novita")` handles the general case
// by passing those ids through verbatim. This explicit map remains for
// the earliest audited gemma-4 regression and as a place to add future
// Novita-specific exceptions if their catalog ever diverges.
var novitaModelMap = map[string]string{
	"google/gemma-4-31b-it":     "google/gemma-4-31b-it",
	"google/gemma-4-26b-a4b-it": "google/gemma-4-26b-a4b-it",
}

// phalaModelMap maps OR-canonical → Phala native.
//
// The 2026-05-12 first attempt routed Phala via the
// upstream-author form (`openai/gpt-5.5`, `anthropic/claude-haiku-4.5`,
// etc.) because /v1/models lists both forms. That returned
// `{"error":{"message":"Invalid API key provided"}}` on every chat
// request even though /v1/models worked with the same key.
//
// Root cause uncovered from Phala's docs at
// https://docs.phala.com/phala-cloud/confidential-ai/confidential-model/confidential-ai-api :
// their example uses `"model": "phala/deepseek-chat-v3-0324"`. The
// `phala/` prefix selects the GPU-TEE-attested confidential tier
// (which our key is entitled to); the upstream-author forms in
// /v1/models go to a non-TEE pass-through tier that our key is
// NOT entitled to, hence 401. Confidential AI keys + TEE
// inference is the entire product reason we use Phala — match it.
//
// Source: live probe of api.redpill.ai/v1/models + Phala
// confidential-ai-api docs on 2026-05-13. Add new entries when
// Phala adds new `phala/...` model aliases.
var phalaModelMap = map[string]string{
	"google/gemma-3-27b-it":            "phala/gemma-3-27b-it",
	"minimax/minimax-m2.5":             "phala/minimax-m2.5",
	"moonshotai/kimi-k2.5":             "phala/kimi-k2.5",
	"moonshotai/kimi-k2.6":             "phala/kimi-k2.6",
	"openai/gpt-oss-120b":              "phala/gpt-oss-120b",
	"openai/gpt-oss-20b":               "phala/gpt-oss-20b",
	"qwen/qwen-2.5-7b-instruct":        "phala/qwen-2.5-7b-instruct",
	"qwen/qwen2.5-vl-72b-instruct":     "phala/qwen2.5-vl-72b-instruct",
	"qwen/qwen3-vl-30b-a3b-instruct":   "phala/qwen3-vl-30b-a3b-instruct",
	"qwen/qwen3.5-27b":                 "phala/qwen3.5-27b",
	"qwen/qwen3.5-397b-a17b":           "phala/qwen3.5-397b-a17b",
	"qwen/qwen3-coder-next":            "phala/qwen3-coder-next",
	"qwen/qwen3-30b-a3b-instruct-2507": "phala/qwen3-30b-a3b-instruct-2507",
	"z-ai/glm-4.7":                     "phala/glm-4.7",
	"z-ai/glm-4.7-flash":               "phala/glm-4.7-flash",
	"z-ai/glm-5":                       "phala/glm-5",
	"z-ai/glm-5.1":                     "phala/glm-5.1",
	"z-ai/glm-5.2":                     "phala/glm-5.2",
	"deepseek/deepseek-v3.2":           "phala/deepseek-v3.2",
	"deepseek/deepseek-chat-v3.1":      "phala/deepseek-chat-v3.1",
	"xiaomi/mimo-v2-flash":             "phala/mimo-v2-flash",
}

// tinfoilModelMap maps OR-canonical → Tinfoil native. Tinfoil
// flattens everything to a bare slug and replaces dots with
// dashes (`kimi-k2.6` → `kimi-k2-6`, `glm-5.2` → `glm-5-2`).
// Without this map, every Tinfoil-routed request for a model
// containing a dot in its version silently 404s. Source:
// `quill-router/scripts/pricing/providers/tinfoil.py`.
var tinfoilModelMap = map[string]string{
	"moonshotai/kimi-k2.6":              "kimi-k2-6",
	"moonshotai/kimi-k2.7-code":         "kimi-k2-7-code",
	"z-ai/glm-5.2":                      "glm-5-2",
	"deepseek/deepseek-v4-pro":          "deepseek-v4-pro",
	"google/gemma-4-31b-it":             "gemma4-31b",
	"meta-llama/llama-3.3-70b-instruct": "llama3-3-70b",
	"openai/gpt-oss-120b":               "gpt-oss-120b",
	"mistralai/voxtral-small-24b":       "voxtral-small-24b",
	"openai/whisper-large-v3-turbo":     "whisper-large-v3-turbo",
	"qwen/qwen3-tts":                    "qwen3-tts",
	"nomic-ai/nomic-embed-text":         "nomic-embed-text",
}

// veniceModelMap maps OR-canonical → Venice native ids. Venice's API uses
// dashed provider-local names (`zai-org-glm-5-2`) and no longer reliably
// aliases OR-style ids.
var veniceModelMap = map[string]string{
	"z-ai/glm-5.2": "zai-org-glm-5-2",
}

// friendliModelMap maps OR-canonical → Friendli native ids. Friendli mixes
// local ids for Llama with upstream-author ids for GLM/Qwen/MiniMax.
var friendliModelMap = map[string]string{
	"meta-llama/llama-3.3-70b-instruct": "meta-llama-3.3-70b-instruct",
	"meta-llama/llama-3.1-8b-instruct":  "meta-llama-3.1-8b-instruct",
	"qwen/qwen3-235b-a22b-2507":         "Qwen/Qwen3-235B-A22B-Instruct-2507",
	"lgai-exaone/k-exaone-236b-a23b":    "LGAI-EXAONE/K-EXAONE-236B-A23B",
	"z-ai/glm-5":                        "zai-org/GLM-5",
	"minimax/minimax-m2.5":              "MiniMaxAI/MiniMax-M2.5",
	"deepseek/deepseek-v3.2":            "deepseek-ai/DeepSeek-V3.2",
	"z-ai/glm-5.1":                      "zai-org/GLM-5.1",
	"z-ai/glm-5.2":                      "zai-org/GLM-5.2",
}

// basetenModelMap maps OR-canonical → Baseten native ids. Baseten's
// /v1/models uses upstream-author mixed-case ids, so the generic strip-author
// fallback would ship bare/lowercase slugs that Baseten does not advertise.
var basetenModelMap = map[string]string{
	"openai/gpt-oss-120b":               "openai/gpt-oss-120b",
	"z-ai/glm-4.7":                      "zai-org/GLM-4.7",
	"moonshotai/kimi-k2.5":              "moonshotai/Kimi-K2.5",
	"z-ai/glm-5":                        "zai-org/GLM-5",
	"nvidia/nemotron-120b-a12b":         "nvidia/Nemotron-120B-A12B",
	"z-ai/glm-5.1":                      "zai-org/GLM-5.1",
	"moonshotai/kimi-k2.6":              "moonshotai/Kimi-K2.6",
	"deepseek/deepseek-v4-pro":          "deepseek-ai/DeepSeek-V4-Pro",
	"nvidia/nemotron-3-ultra-550b-a55b": "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B",
	"z-ai/glm-5.2":                      "zai-org/GLM-5.2",
	"moonshotai/kimi-k2.7-code":         "moonshotai/Kimi-K2.7-Code",
	"thinkingmachines/inkling-1m":       "thinkingmachines/inkling",
}

var thinkingMachinesModelMap = map[string]string{
	"thinkingmachines/inkling": "thinkingmachines/Inkling:peft:262144",
}

// waferModelMap maps OR-canonical → Wafer native ids. Wafer's ids are short
// provider-local names like "GLM-5.2" and "Kimi-K2.7-Code"; they do not carry
// the OR author namespace.
var waferModelMap = map[string]string{
	"z-ai/glm-5.1":               "GLM-5.1",
	"z-ai/glm-5.2":               "GLM-5.2",
	"moonshotai/kimi-k2.6":       "Kimi-K2.6",
	"moonshotai/kimi-k2.7-code":  "Kimi-K2.7-Code",
	"qwen/qwen3.5-397b-a17b":     "Qwen3.5-397B-A17B",
	"qwen/qwen3.6-35b-a3b":       "Qwen3.6-35B-A3B",
	"qwen/qwen3.6-max-preview":   "qwen3.6-max-preview",
	"qwen/qwen3.7-max":           "qwen3.7-max",
	"deepseek/deepseek-v4-flash": "deepseek-v4-flash",
	"deepseek/deepseek-v4-pro":   "deepseek-v4-pro",
	"minimax/minimax-m3":         "MiniMax-M3",
}

// crusoeModelMap maps OR-canonical → Crusoe Managed Inference native ids.
// Crusoe's /v1/models is OpenAI-compatible but case-sensitive, and some rows
// intentionally diverge from the usual author namespace (`zai/GLM-5.2` rather
// than `zai-org/...`, `Deepseek-V4-Flash` with lowercase "s"). Keep exact
// native ids here so directModelID never falls through to a guessed slug.
var crusoeModelMap = map[string]string{
	"deepseek/deepseek-v3-0324":                     "deepseek-ai/DeepSeek-V3-0324",
	"deepseek/deepseek-v4-flash":                    "deepseek-ai/Deepseek-V4-Flash",
	"deepseek/deepseek-v4-pro":                      "deepseek-ai/DeepSeek-V4-Pro",
	"google/gemma-4-31b-it":                         "google/gemma-4-31b-it",
	"meta-llama/llama-3.3-70b-instruct":             "meta-llama/Llama-3.3-70B-Instruct",
	"moonshotai/kimi-k2.6":                          "moonshotai/Kimi-K2.6",
	"nvidia/nemotron-3-nano-30b-a3b":                "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
	"nvidia/nemotron-3-nano-omni-reasoning-30b-a3b": "nvidia/Nemotron-3-Nano-Omni-Reasoning-30B-A3B",
	"nvidia/nemotron-3-super-120b-a12b":             "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B",
	"nvidia/nemotron-3-ultra-550b":                  "nvidia/NVIDIA-Nemotron-3-Ultra-550B",
	"openai/gpt-oss-120b":                           "openai/gpt-oss-120b",
	"qwen/qwen3-235b-a22b-2507":                     "Qwen/Qwen3-235B-A22B-Instruct-2507",
	"yutori/n1.5":                                   "yutori/n1.5",
	"z-ai/glm-5.1":                                  "zai/GLM-5.1",
	"z-ai/glm-5.2":                                  "zai/GLM-5.2",
}

// makoraModelMap maps OR-canonical → Makora Inference native ids. Makora's
// OpenAI-compatible /v1/models feed uses upstream-author mixed-case ids, plus a
// custom model-specific Llama FP8 row. Keep exact ids here so requests never
// fall through to the generic strip-author fallback.
var makoraModelMap = map[string]string{
	"deepseek/deepseek-v4-flash":        "deepseek-ai/DeepSeek-V4-Flash",
	"deepseek/deepseek-v4-pro":          "deepseek-ai/DeepSeek-V4-Pro",
	"google/gemma-4-26b-a4b-it":         "google/gemma-4-26B-A4B",
	"z-ai/glm-5.2":                      "zai-org/GLM-5.2-FP8",
	"z-ai/glm-5.2-nvfp4":                "zai-org/GLM-5.2-NVFP4",
	"moonshotai/kimi-k2.7-code":         "moonshotai/Kimi-K2.7-Code",
	"amd/llama-3.3-70b-instruct-fp8-kv": "amd/Llama-3.3-70B-Instruct-FP8-KV",
	"meta-llama/llama-3.3-70b-instruct": "meta-llama/Llama-3.3-70B-Instruct",
	"qwen/qwen3.6-27b":                  "unsloth/Qwen3.6-27B-NVFP4",
	"qwen/qwen3.6-35b-a3b":              "unsloth/Qwen3.6-35B-A3B-NVFP4",
}

var waferZDRNativeModels = map[string]struct{}{
	"GLM-5.1": {},
	"GLM-5.2": {},
	// Wafer withdrew ZDR for Kimi-K2.6 on 2026-06-26; the control-plane
	// catalog now serves it at standard tier (quill-router leaderboard-fixes).
	"Qwen3.5-397B-A17B": {},
	"deepseek-v4-flash": {},
	"deepseek-v4-pro":   {},
}

func waferModelSupportsZDR(upstreamID string) bool {
	_, ok := waferZDRNativeModels[upstreamID]
	return ok
}

var directModelMap = map[string]string{
	"anthropic/claude-sonnet-5":   "claude-sonnet-5",
	"anthropic/claude-opus-4.8":   "claude-opus-4-8",
	"anthropic/claude-opus-4.7":   "claude-opus-4-7",
	"anthropic/claude-sonnet-4.6": "claude-sonnet-4-6",
	// Pre-4.6 models must use DATED ids: Anthropic retires undated aliases
	// at deprecation while dated snapshots serve until formal retirement.
	// Docs: platform.claude.com models overview; observed with
	// claude-opus-4-1 on 2026-06-21. 4.6+ dateless ids are pinned snapshots
	// and need no dates.
	"anthropic/claude-haiku-4.5":  "claude-haiku-4-5-20251001",
	"anthropic/claude-sonnet-4.5": "claude-sonnet-4-5-20250929",
	"anthropic/claude-opus-4.5":   "claude-opus-4-5-20251101",
	"anthropic/claude-opus-4.1":   "claude-opus-4-1-20250805",
	"anthropic/claude-3-5-sonnet": "claude-3-5-sonnet-20241022",
	// Original Claude 4.0 GA: Anthropic serves these only under the dated
	// snapshot id. The anthropic path calls directModelID FIRST (this map),
	// so the remap must live here (not just anthropic.go's modelIDMap, which
	// only sees the already-stripped id). Verified 2026-06-04.
	"anthropic/claude-opus-4":          "claude-opus-4-20250514",
	"anthropic/claude-sonnet-4":        "claude-sonnet-4-20250514",
	"meta-llama/llama-3.1-8b-instruct": "llama3.1-8b",
	"llama-3.1-8b-instruct":            "llama3.1-8b",
	"openai/gpt-oss-120b":              "gpt-oss-120b",
	"qwen/qwen3-235b-a22b-2507":        "qwen-3-235b-a22b-instruct-2507",
	"z-ai/glm-4.7":                     "zai-glm-4.7",
	"moonshotai/kimi-k2.7-code":        "moonshotai/Kimi-K2.7-Code",
	// Mistral's API rejects the bare "mistral-large" ("Invalid model");
	// it serves the alias "mistral-large-latest" (-> mistral-large-2512).
	// Verified vs api.mistral.ai/v1/models 2026-06-04.
	"mistralai/mistral-large":                  "mistral-large-latest",
	"mistralai/mistral-small-3.2-24b-instruct": "mistral-small-2506",
	"mistralai/mistral-nemo":                   "open-mistral-nemo",
	"openai/gpt-4o-mini":                       "gpt-4o-mini",
	"google/gemini-1.5-flash":                  "gemini-1.5-flash",
	"vertex/gemini-2.5-flash":                  "gemini-2.5-flash",
}

func normalizeDirectProvider(provider string) string {
	slug := strings.ToLower(strings.TrimSpace(provider))
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "_", "-")
	switch slug {
	case "google", "google-ai", "gemini":
		return "gemini"
	case "google-ai-studio", "ai-studio":
		return "google-ai-studio"
	case "google-vertex", "google-vertex-ai", "vertex-ai":
		return "google-vertex"
	case "moonshot", "moonshot-ai", "moonshotai", "kimi":
		return "kimi"
	case "fireworks", "fireworks-ai":
		return "fireworks"
	case "mistral-ai", "mistralai", "mistral":
		return "mistral"
	case "z-ai", "zhipu", "zhipuai", "zai":
		return "zai"
	case "x-ai", "xai", "grok":
		return "grok"
	case "novita", "novita-ai":
		return "novita"
	case "phala", "redpill", "red-pill":
		return "phala"
	case "silicon-flow", "siliconflow":
		return "siliconflow"
	case "tinfoil", "tinfoil-sh":
		return "tinfoil"
	case "venice", "venice-ai":
		return "venice"
	case "parasail", "parasail-ai", "parasail-io":
		return "parasail"
	case "lightning", "lightning-ai":
		return "lightning"
	case "gmi", "gmi-cloud", "gmicloud":
		return "gmi"
	case "deepinfra", "deep-infra", "deep_infra":
		return "deepinfra"
	case "friendli", "friendli-ai", "friendliai":
		return "friendli"
	case "baseten", "base-ten":
		return "baseten"
	case "thinkingmachines", "thinking-machines", "tinker":
		return "thinkingmachines"
	case "wafer", "wafer-ai":
		return "wafer"
	case "makora", "makora-ai", "makora_inference", "makora-inference":
		return "makora"
	case "nebius", "nebius-ai", "nebius-ai-studio", "tokenfactory", "token-factory":
		return "nebius"
	case "minimax", "mini-max", "minimax-ai", "minimaxai":
		return "minimax"
	case "cohere", "cohere-ai":
		return "cohere"
	default:
		return slug
	}
}

// defaultHTTPClient returns the default outbound HTTP client used by
// every LLM-provider client (anthropic, openai-compatible, etc.).
//
// On GCP-side enclaves this dials directly over the network — the
// Confidential Space VM has plain internet egress.
//
// On AWS-side enclaves (cloud_aws build tag), the Nitro Enclave has
// no network at all; outbound HTTPS must travel via vsock to the
// parent host's `vsock-proxy` daemon. The cloud_aws variant of this
// function (in http_client_aws.go) returns a vsockhttp-backed client
// with a Tunnel per upstream hostname.
//
// See:
//   - http_client_direct.go     (!cloud_aws — net.Dialer)
//   - http_client_aws.go        (cloud_aws — vsockhttp tunnel map)
//   - parent's vsock-proxy.yaml (matching CID:port allowlist)
