package llm

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type upstreamHTTPError struct {
	status int
	body   string
}

func (e *upstreamHTTPError) Error() string {
	return fmt.Sprintf("llm/upstream: http %d: %s", e.status, e.body)
}

// HTTPStatusFromError returns the upstream HTTP status code carried by err when
// it originated as a non-2xx upstream response, and ok=false otherwise (e.g.
// transport, timeout, or cancellation errors that never reached an HTTP
// status). Used by the gateway's provider-failover logic to decide which
// failures are worth retrying on the next authorized provider.
func HTTPStatusFromError(err error) (status int, ok bool) {
	var httpErr *upstreamHTTPError
	if errors.As(err, &httpErr) {
		return httpErr.status, true
	}
	return 0, false
}

// translateOpenAIStreamToAnthropic reads OpenAI Chat Completions SSE chunks
// and writes native Anthropic SSE events for the existing adapter pipeline.
func translateOpenAIStreamToAnthropic(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	stopReason := "end_turn"
	toolCalls := map[int]*openAIToolCallAccumulator{}
	var toolOrder []int
	var usage *openAIStreamUsage
	serviceTier := ""
	thinkingStarted := false
	var citations []string
	var searchResults []qtypes.ProviderSearchResult
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := line[len("data: "):]
		if payload == "[DONE]" {
			break
		}

		var chunk struct {
			ServiceTier   string                        `json:"service_tier"`
			Citations     []string                      `json:"citations"`
			SearchResults []qtypes.ProviderSearchResult `json:"search_results"`
			Choices       []struct {
				Delta struct {
					Content string `json:"content"`
					// Several Chinese OpenAI-compatible providers (Z.AI/Zhipu,
					// Moonshot in some configs) emit chain-of-thought tokens
					// in `reasoning_content` and only fill `content` for the
					// final answer. Keep it on the enclave's internal
					// thinking channel so downstream adapters can stream it as
					// reasoning_content without mixing it into the visible
					// assistant answer.
					ReasoningContent string `json:"reasoning_content"`
					ToolCalls        []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			// usage arrives on the final stream_options.include_usage chunk
			// (choices: []) — byok.go requests it from every OpenAI-
			// compatible upstream. Some providers instead attach usage to
			// the last content chunk; both shapes land here.
			Usage *openAIStreamUsage `json:"usage"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		if chunk.ServiceTier != "" {
			serviceTier = chunk.ServiceTier
		}
		citations = mergeProviderCitations(citations, chunk.Citations)
		searchResults = mergeProviderSearchResults(searchResults, chunk.SearchResults)
		if chunk.Usage != nil {
			usage = chunk.Usage
		}
		if usage == nil && serviceTier != "" {
			usage = &openAIStreamUsage{}
		}
		if usage != nil && serviceTier != "" {
			usage.ServiceTier = serviceTier
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		choice := chunk.Choices[0]

		if choice.Delta.Content != "" {
			if err := writeAnthropicTextDelta(w, choice.Delta.Content); err != nil {
				return err
			}
		} else if choice.Delta.ReasoningContent != "" {
			if !thinkingStarted {
				thinkingStarted = true
				if err := writeAnthropicThinkingStart(w, 0); err != nil {
					return err
				}
			}
			if err := writeAnthropicThinkingDelta(w, 0, choice.Delta.ReasoningContent); err != nil {
				return err
			}
		}
		for _, delta := range choice.Delta.ToolCalls {
			call := toolCalls[delta.Index]
			if call == nil {
				id := delta.ID
				if id == "" {
					id = fmt.Sprintf("call_%d", delta.Index)
				}
				call = &openAIToolCallAccumulator{ID: id, Name: delta.Function.Name}
				toolCalls[delta.Index] = call
				toolOrder = append(toolOrder, delta.Index)
				if err := writeAnthropicToolStart(w, delta.Index, call.ID, call.Name); err != nil {
					return err
				}
			}
			if call.Name == "" && delta.Function.Name != "" {
				call.Name = delta.Function.Name
			}
			if delta.Function.Arguments != "" {
				call.Arguments += delta.Function.Arguments
				if err := writeAnthropicToolDelta(w, delta.Index, delta.Function.Arguments); err != nil {
					return err
				}
			}
		}
		if choice.FinishReason != nil && *choice.FinishReason != "" {
			stopReason = mapOpenAIFinishReason(*choice.FinishReason)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("llm/openai-stream: scan: %w", err)
	}

	for _, index := range toolOrder {
		if err := writeAnthropicToolStop(w, index); err != nil {
			return err
		}
	}
	return writeAnthropicStop(w, stopReason, usage, citations, searchResults)
}

type openAIToolCallAccumulator struct {
	ID        string
	Name      string
	Arguments string
}

// openAIStreamUsage is the OpenAI chat-completions stream usage object.
// Also constructed by the Gemini path from usageMetadata.
type openAIStreamUsage struct {
	PromptTokens            int                       `json:"prompt_tokens"`
	CompletionTokens        int                       `json:"completion_tokens"`
	TotalTokens             int                       `json:"total_tokens"`
	CompletionTokensDetails *openAIStreamUsageDetails `json:"completion_tokens_details"`
	PromptTokensDetails     *openAIPromptTokenDetails `json:"prompt_tokens_details"`
	// Non-standard prompt-cache fields some OpenAI-compatible providers use
	// INSTEAD of prompt_tokens_details.cached_tokens (verified 2026-06-20):
	//   Moonshot/Kimi (kimi-k2.* automatic prefix cache) -> top-level usage.cached_tokens
	//   DeepSeek ("context caching on disk", on by default) -> usage.prompt_cache_hit_tokens
	// Without these, those providers' cache hits are silently dropped because
	// the gateway only read the OpenAI-standard nested field.
	CachedTokensTop      int    `json:"cached_tokens"`
	PromptCacheHitTokens int    `json:"prompt_cache_hit_tokens"`
	ServiceTier          string `json:"-"`
}

// cachedTokens returns the prompt-cache hit count, normalizing across the
// field each provider reports it in. The OpenAI-standard nested placement
// wins; then Moonshot/Kimi's top-level usage.cached_tokens; then DeepSeek's
// prompt_cache_hit_tokens. The Gemini path sets PromptTokensDetails directly,
// so it keeps taking precedence unchanged.
func (u *openAIStreamUsage) cachedTokens() int {
	if u == nil {
		return 0
	}
	cached := 0
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.CachedTokens > 0 {
		cached = u.PromptTokensDetails.CachedTokens
	} else if u.CachedTokensTop > 0 {
		cached = u.CachedTokensTop
	} else if u.PromptCacheHitTokens > 0 {
		cached = u.PromptCacheHitTokens
	}
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.OrchestrationInputCachedTokens > 0 {
		cached += u.PromptTokensDetails.OrchestrationInputCachedTokens
	}
	return cached
}

// inputTokens includes provider-side orchestration input. Sakana's Fugu
// routes report the final model prompt in prompt_tokens and the panel/router
// work in prompt_tokens_details.orchestration_input_tokens; both are billable.
func (u *openAIStreamUsage) inputTokens() int {
	if u == nil {
		return 0
	}
	input := u.PromptTokens
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.OrchestrationInputTokens > 0 {
		input += u.PromptTokensDetails.OrchestrationInputTokens
	}
	return input
}

// priceTierInputTokens preserves the provider's original prompt count when
// the request also incurred separately billable orchestration work. Sakana
// selects Fugu's long-context tier from this count, not from the additive
// orchestration tokens included by inputTokens.
func (u *openAIStreamUsage) priceTierInputTokens() int {
	if u == nil || u.PromptTokensDetails == nil ||
		u.PromptTokensDetails.OrchestrationInputTokens <= 0 {
		return 0
	}
	return u.PromptTokens
}

// outputTokens returns every provider-reported non-input token. Most OpenAI-
// compatible providers include reasoning inside completion_tokens. Google AI
// Studio currently reports visible tokens in completion_tokens while including
// hidden thinking only in total_tokens. Prefer the larger coherent total so
// settlement cannot silently underbill those tokens.
func (u *openAIStreamUsage) outputTokens() int {
	if u == nil {
		return 0
	}
	output := u.CompletionTokens
	if u.CompletionTokensDetails != nil && u.CompletionTokensDetails.OrchestrationOutputTokens > 0 {
		output += u.CompletionTokensDetails.OrchestrationOutputTokens
	}
	if fromTotal := u.TotalTokens - u.PromptTokens; fromTotal > output {
		output = fromTotal
	}
	return output
}

func (u *openAIStreamUsage) reasoningTokens() int {
	if u == nil {
		return 0
	}
	if u.CompletionTokensDetails != nil && u.CompletionTokensDetails.ReasoningTokens > 0 {
		return u.CompletionTokensDetails.ReasoningTokens
	}
	// When an upstream omits completion_tokens_details, the unexplained
	// total-token residual is the only authoritative count for hidden work.
	if residual := u.outputTokens() - u.CompletionTokens; residual > 0 {
		return residual
	}
	return 0
}

type openAIStreamUsageDetails struct {
	ReasoningTokens           int `json:"reasoning_tokens"`
	OrchestrationOutputTokens int `json:"orchestration_output_tokens"`
}

type openAIPromptTokenDetails struct {
	CachedTokens                   int `json:"cached_tokens"`
	OrchestrationInputTokens       int `json:"orchestration_input_tokens"`
	OrchestrationInputCachedTokens int `json:"orchestration_input_cached_tokens"`
}

func writeAnthropicTextDelta(w io.Writer, text string) error {
	payload := map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "text_delta", "text": text},
	}
	body, _ := json.Marshal(payload)
	_, err := fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", body)
	return err
}

func writeAnthropicThinkingStart(w io.Writer, index int) error {
	payload := map[string]any{
		"type":  "content_block_start",
		"index": index,
		"content_block": map[string]any{
			"type":     "thinking",
			"thinking": "",
		},
	}
	body, _ := json.Marshal(payload)
	_, err := fmt.Fprintf(w, "event: content_block_start\ndata: %s\n\n", body)
	return err
}

func writeAnthropicThinkingDelta(w io.Writer, index int, text string) error {
	payload := map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{
			"type":     "thinking_delta",
			"thinking": text,
		},
	}
	body, _ := json.Marshal(payload)
	_, err := fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", body)
	return err
}

func writeAnthropicToolStart(w io.Writer, index int, id string, name string) error {
	payload := map[string]any{
		"type":  "content_block_start",
		"index": index,
		"content_block": map[string]any{
			"type":  "tool_use",
			"id":    id,
			"name":  name,
			"input": map[string]any{},
		},
	}
	body, _ := json.Marshal(payload)
	_, err := fmt.Fprintf(w, "event: content_block_start\ndata: %s\n\n", body)
	return err
}

func writeAnthropicToolDelta(w io.Writer, index int, partialJSON string) error {
	payload := map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{
			"type":         "input_json_delta",
			"partial_json": partialJSON,
		},
	}
	body, _ := json.Marshal(payload)
	_, err := fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", body)
	return err
}

func writeAnthropicToolStop(w io.Writer, index int) error {
	payload := map[string]any{
		"type":  "content_block_stop",
		"index": index,
	}
	body, _ := json.Marshal(payload)
	_, err := fmt.Fprintf(w, "event: content_block_stop\ndata: %s\n\n", body)
	return err
}

func writeAnthropicStop(
	w io.Writer,
	stopReason string,
	usage *openAIStreamUsage,
	citations []string,
	searchResults []qtypes.ProviderSearchResult,
) error {
	mDelta := map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stopReason},
	}
	if len(citations) > 0 {
		mDelta["trustedrouter_citations"] = citations
	}
	if len(searchResults) > 0 {
		mDelta["trustedrouter_search_results"] = searchResults
	}
	if usage != nil {
		// Relay the upstream-reported usage on the synthetic message_delta.
		// Native Anthropic splits input (message_start) from output
		// (message_delta) but this event is OUR internal contract with
		// adapter.TransformStreamCapture/CollectAnthropicText, which read
		// whichever keys are present.
		usageBody := map[string]any{
			"input_tokens":  usage.inputTokens(),
			"output_tokens": usage.outputTokens(),
		}
		if tierInput := usage.priceTierInputTokens(); tierInput > 0 {
			usageBody["price_tier_input_tokens"] = tierInput
		}
		if reasoningTokens := usage.reasoningTokens(); reasoningTokens > 0 {
			usageBody["reasoning_tokens"] = reasoningTokens
		}
		if cached := usage.cachedTokens(); cached > 0 {
			usageBody["cache_read_input_tokens"] = cached
		}
		if usage.ServiceTier != "" {
			usageBody["service_tier"] = usage.ServiceTier
		}
		mDelta["usage"] = usageBody
	}
	body, _ := json.Marshal(mDelta)
	if _, err := fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", body); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	return err
}

func mergeProviderCitations(existing, incoming []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	out := make([]string, 0, len(existing)+len(incoming))
	for _, values := range [][]string{existing, incoming} {
		for _, raw := range values {
			clean := safeProviderCitationURL(raw)
			if clean == "" {
				continue
			}
			if _, duplicate := seen[clean]; duplicate {
				continue
			}
			seen[clean] = struct{}{}
			out = append(out, clean)
			if len(out) >= 50 {
				return out
			}
		}
	}
	return out
}

func mergeProviderSearchResults(existing, incoming []qtypes.ProviderSearchResult) []qtypes.ProviderSearchResult {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	out := make([]qtypes.ProviderSearchResult, 0, len(existing)+len(incoming))
	for _, values := range [][]qtypes.ProviderSearchResult{existing, incoming} {
		for _, result := range values {
			result.URL = safeProviderCitationURL(result.URL)
			if result.URL == "" {
				continue
			}
			if _, duplicate := seen[result.URL]; duplicate {
				continue
			}
			seen[result.URL] = struct{}{}
			result.Title = truncateProviderMetadata(result.Title, 512)
			result.Date = truncateProviderMetadata(result.Date, 128)
			result.LastUpdated = truncateProviderMetadata(result.LastUpdated, 128)
			result.Snippet = truncateProviderMetadata(result.Snippet, 8192)
			result.Source = truncateProviderMetadata(result.Source, 64)
			out = append(out, result)
			if len(out) >= 50 {
				return out
			}
		}
	}
	return out
}

func safeProviderCitationURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	parsed.User = nil
	return truncateProviderMetadata(parsed.String(), 4096)
}

func truncateProviderMetadata(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func mapOpenAIFinishReason(reason string) string {
	switch reason {
	case "stop":
		return "end_turn"
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	case "content_filter":
		return qtypes.SyntheticStopReasonContentFilter
	default:
		return "end_turn"
	}
}
