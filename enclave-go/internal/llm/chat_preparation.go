package llm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// ChatPreparationOptions contains already resolved, trusted adapter inputs.
// Secrets, image fetching and Privatemode random cache isolation stay at dispatch.
type ChatPreparationOptions struct {
	ProviderCacheScope string
	privateWire        *openAICompatibleRequest
}

// PreparedChatRequest owns the exact ordinary-dispatch wire bytes and routing metadata.
type PreparedChatRequest struct {
	Bytes              []byte
	Path               string
	DecisionCompletion bool
	NativeResponses    bool
}

// PrepareChatRequest is the shared, side-effect-free ordinary Chat preparation:
// no I/O, secret resolution, randomness, clock reads, or input mutation. Messages
// must already be normalized (including system additions and fetched media).
// Client stream=false still uses upstream streaming, except structured decisions,
// exactly as ordinary dispatch does. Callers must send Bytes without rewriting.
func PrepareChatRequest(provider, upstreamModel string, req *qtypes.OpenAIChatRequest, body *qtypes.AnthropicMessagesRequest, msgs []ChatMessage, options ChatPreparationOptions) (PreparedChatRequest, error) {
	model := upstreamModel
	if req != nil {
		model = req.Model
	}
	upstreamID := directModelID(provider, model, upstreamModel)
	if strings.TrimSpace(upstreamID) == "" {
		return PreparedChatRequest{}, fmt.Errorf("llm/%s: missing authorized upstream model", provider)
	}
	if err := validateKimiReasoningEffort(provider, req, upstreamID); err != nil {
		return PreparedChatRequest{}, err
	}
	reqBody := buildOpenAICompatibleRequest(provider, upstreamID, req, body, msgs)
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
		reqBody.UserCacheSecret = strings.TrimSpace(options.ProviderCacheScope)
	}
	if normalizeDirectProvider(provider) == "privatemode" {
		if options.privateWire == nil {
			return PreparedChatRequest{}, fmt.Errorf("llm/privatemode: unresolved cache isolation")
		}
		reqBody.Thinking, reqBody.Reasoning = nil, nil
		reqBody.ReasoningEffort = options.privateWire.ReasoningEffort
		reqBody.CacheSalt = options.privateWire.CacheSalt
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
