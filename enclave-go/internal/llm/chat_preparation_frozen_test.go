package llm

// Frozen from 4a4f0695 byok.go. Deliberately independent of the extracted builder.
import (
	"encoding/json"
	"fmt"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"net/http"
	"strings"
)

func frozenBuildOpenAICompatibleRequest(
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
		if !kimiUsesFixedSampling(provider, upstreamID) {
			reqBody.TopP = body.TopP
		}
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
		if normalizeDirectProvider(provider) == "openai" {
			reqBody.ServiceTier = strings.TrimSpace(req.ServiceTier)
			if reqBody.ServiceTier == "" {
				// Keep billing predictable even if the operator's OpenAI
				// project default changes to Priority later.
				reqBody.ServiceTier = "default"
			}
		}
		reqBody.Reasoning = req.Reasoning
		reqBody.ReasoningEffort = req.ReasoningEffort
		reqBody.TopA = req.TopA
		reqBody.MinP = req.MinP
		reqBody.RepetitionPenalty = req.RepetitionPenalty
		reqBody.Tools = req.Tools
		reqBody.ToolChoice = req.ToolChoice
		reqBody.ParallelToolCalls = req.ParallelTools
		reqBody.Seed = req.Seed
		reqBody.FrequencyPenalty = req.FrequencyPenalty
		reqBody.PresencePenalty = req.PresencePenalty
		reqBody.LogitBias = req.LogitBias
		reqBody.Logprobs = req.Logprobs
		reqBody.TopLogprobs = req.TopLogprobs
		reqBody.Stop = req.Stop
		reqBody.Prediction = req.Prediction
		reqBody.PromptCacheKey = req.PromptCacheKey
		reqBody.PromptCacheOptions = req.PromptCacheOptions
		if len(req.ResponseFormat) > 0 {
			reqBody.ResponseFormat = req.ResponseFormat
		}
		applyChatReasoningEffort(provider, req, body, &reqBody)
		applyHybridReasoningControl(provider, req, &reqBody)
		if kimiToolsNeedThinkingDisabled(provider, upstreamID, req.Tools) {
			reqBody.Thinking = map[string]string{"type": "disabled"}
		}
		if kimiUsesFixedSampling(provider, upstreamID) {
			reqBody.FrequencyPenalty = nil
			reqBody.PresencePenalty = nil
		}
	}
	// Azure Foundry's OpenAI-compatible Kimi deployments reject the
	// Moonshot-native `thinking` extension outright. Preserve tools and
	// tool_choice when present, but always omit thinking rather than asking
	// K2.5/K2.6 to disable it as the direct Moonshot API requires. Keep this
	// outside the req != nil block: the provider contract is unconditional.
	if isAzureKimiDeployment(provider, upstreamID) {
		reqBody.Thinking = nil
	}
	if effort := googleAIStudioDefaultReasoningEffort(provider, upstreamID, req, body); effort != "" {
		reqBody.ReasoningEffort = effort
	}
	reqBody.ReasoningEffort = googleAIStudioCompatibleReasoningEffort(
		provider,
		upstreamID,
		reqBody.ReasoningEffort,
	)
	reqBody.Reasoning = googleAIStudioCompatibleReasoning(provider, upstreamID, reqBody.Reasoning)
	// Engy's Qwen 3.6 endpoint otherwise returns its complete answer only in
	// reasoning_content while leaving message.content empty. Disable thinking
	// at the provider chat-template boundary so ordinary OpenAI clients receive
	// a usable visible answer. Keep the override scoped to this verified route.
	if normalizeDirectProvider(provider) == "engy" && strings.EqualFold(strings.TrimSpace(upstreamID), "qwen3.6-35b-a3b") {
		reqBody.ChatTemplateKwargs = &chatTemplateKwargs{EnableThinking: false}
	}
	if supportsStreamUsageOption(provider, upstreamID) {
		reqBody.StreamOptions = &openAICompatibleStreamOptions{IncludeUsage: true}
	}
	if normalizeDirectProvider(provider) == "perplexity" {
		// Perplexity's Sonar request fee depends on search context size. The
		// control plane reserves the exact low-context fee, so the enclave must
		// pin that same tier instead of accepting an account or API default.
		reqBody.SearchContextSize = "low"
	}
	return reqBody
}

func frozenPrepareChatRequest(provider, upstreamID string, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, msgs []chatMessage, scope string) (PreparedChatRequest, error) {
	reqBody := frozenBuildOpenAICompatibleRequest(provider, upstreamID, req, body, msgs)
	// Wharf omits decision confidence/probabilities from SSE. Fetch this small
	// task result once as JSON, then use the same response pipeline for both
	// caller modes. Other Neurometric models keep incremental upstream streams.
	decisionCompletion := normalizeDirectProvider(provider) == "neurometric" && upstreamID == "neurometric/structured-decisions"
	if decisionCompletion {
		reqBody.Stream = false
		reqBody.StreamOptions = nil
	}
	if normalizeDirectProvider(provider) == "tencent" {
		if err := validateTencentThinking(reqBody); err != nil {
			return PreparedChatRequest{}, err
		}
	}
	if explicitHybridThinkingConflict(provider, req, reqBody) {
		return PreparedChatRequest{}, &upstreamHTTPError{status: http.StatusBadRequest, body: "reasoning on is not supported with tools on this provider route"}
	}
	if normalizeDirectProvider(provider) == "tinfoil" {
		reqBody.UserCacheSecret = strings.TrimSpace(scope)
	}
	if normalizeDirectProvider(provider) == "privatemode" {
		if err := preparePrivatemodeWire(req, body, &reqBody, scope); err != nil {
			return PreparedChatRequest{}, err
		}
	}
	var err error
	var payload any = reqBody
	path := directChatCompletionsPath(provider)
	nativeResponses := useOpenAIResponses(provider, reqBody)
	if nativeResponses {
		// Chat normalization retains effort only. Responses also understands
		// summary preferences; validate the original object in its wire builder.
		if req != nil {
			reqBody.Reasoning = req.Reasoning
		}
		payload, err = buildOpenAIResponsesRequest(reqBody)
		if err != nil {
			return PreparedChatRequest{}, err
		}
		path = "/responses"
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return PreparedChatRequest{}, fmt.Errorf("llm/%s: marshal body: %w", provider, err)
	}
	return PreparedChatRequest{bodyBytes, path, decisionCompletion, nativeResponses}, nil
}
