package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func maybeServeChatWebSearch(
	ctx context.Context,
	conn io.Writer,
	req *types.OpenAIChatRequest,
	br llm.Client,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestLogID string,
) bool {
	if req == nil || req.Response == nil || req.Response.WebSearch == nil {
		return false
	}
	if err := validateResponsesWebSearchPrivacy(req); err != nil {
		writeAdapterOpenAIError(conn, err)
		return true
	}
	if enclaveWebSearchClient == nil {
		writeOpenAIError(conn, 503, "web search is unavailable", "server_error", "web_search_unavailable", "tools")
		return true
	}
	if trGateway == nil || !trGateway.Enabled() {
		writeOpenAIError(conn, 503, "web search requires the TrustedRouter gateway", "server_error", "web_search_unavailable", "tools")
		return true
	}
	if err := preflightResponsesWebSearchPrivacy(ctx, req, trGateway, bearer); err != nil {
		writeResponsesWebSearchError(conn, err)
		return true
	}

	requestID := newRequestID()
	rootID := strings.TrimSpace(req.IdempotencyKey)
	if rootID == "" {
		rootID = requestID
	}
	runner := liveResponsesWebSearchModelRunner{
		br: br, trGateway: trGateway, secretCache: secretCache,
		bearer: bearer, requestLogID: requestLogID,
	}
	requestedModel := req.Model
	started := time.Now()
	if !req.Stream {
		outcome, err := executeResponsesWebSearch(ctx, req, runner, enclaveWebSearchClient, rootID, nil)
		if err != nil {
			logResponsesWebSearchEnd(requestLogID, started, outcome, err)
			writeResponsesWebSearchError(conn, err)
			return true
		}
		logResponsesWebSearchEnd(requestLogID, started, outcome, nil)
		serveChatWebSearchJSON(conn, requestID, requestedModel, outcome)
		return true
	}

	if err := writeResponseHead(conn, http.StatusOK, "text/event-stream"); err != nil {
		return true
	}
	chunked := newChunkedWriter(conn)
	defer chunked.Close()
	emitter := newChatWebSearchEmitter(chunked, requestID, requestedModel, req)
	if err := emitter.Start(); err != nil {
		return true
	}
	outcome, err := executeResponsesWebSearch(ctx, req, runner, enclaveWebSearchClient, rootID, emitter)
	if err != nil {
		logResponsesWebSearchEnd(requestLogID, started, outcome, err)
		_ = emitter.Fail(err)
		_ = chunked.Complete()
		return true
	}
	logResponsesWebSearchEnd(requestLogID, started, outcome, nil)
	if err := emitter.Finish(outcome); err != nil {
		return true
	}
	_ = chunked.Complete()
	return true
}

func serveChatWebSearchJSON(
	conn io.Writer,
	requestID string,
	model string,
	outcome responsesWebSearchOutcome,
) {
	text, _ := ensureWebSearchCitations(outcome.Final.Result.Text, outcome.WebCalls, nil)
	citations, searchResults := chatWebSearchProvenance(outcome)
	usage := aggregateWebSearchStreamUsage(outcome)
	var body bytes.Buffer
	if err := adapter.WriteChatCompletionResponseWithProvenance(
		&body,
		requestID,
		model,
		text,
		adapter.JoinThinking(outcome.Final.Result.Thinking),
		visibleWebSearchToolCalls(outcome.Final.Result.ToolCalls),
		outcome.InputTokens,
		outcome.OutputTokens,
		usage,
		time.Now().Unix(),
		outcome.Final.Result.FinishReason,
		citations,
		searchResults,
	); err != nil {
		writeOpenAIError(conn, 500, "chat completion encoding error", "server_error", "internal_error", "")
		return
	}
	annotated, err := annotateChatWebSearchUsage(body.Bytes(), outcome)
	if err != nil {
		writeOpenAIError(conn, 500, "chat completion encoding error", "server_error", "internal_error", "")
		return
	}
	writeJSONResponse(conn, http.StatusOK, annotated)
}

func annotateChatWebSearchUsage(body []byte, outcome responsesWebSearchOutcome) ([]byte, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	usage, _ := payload["usage"].(map[string]any)
	if usage == nil {
		usage = map[string]any{}
		payload["usage"] = usage
	}
	providerUsage := responsesWebSearchProviderUsage(outcome)
	usage["cost_microdollars"] = outcome.TotalCostMicrodollars
	usage["total_cost_microdollars"] = outcome.TotalCostMicrodollars
	usage["provider_usage"] = providerUsage
	usage["server_tool_use"] = map[string]any{"web_search_requests": len(outcome.WebCalls)}
	applyUsageProviderSummary(usage, providerUsage)
	payload["trustedrouter"] = map[string]any{"routing": providerUsage}
	return json.Marshal(payload)
}

func chatWebSearchProvenance(outcome responsesWebSearchOutcome) ([]string, []types.ProviderSearchResult) {
	citations := append([]string(nil), outcome.Final.Result.Citations...)
	results := append([]types.ProviderSearchResult(nil), outcome.Final.Result.SearchResults...)
	for _, source := range uniqueWebSearchSources(outcome.WebCalls) {
		citations = append(citations, source.URL)
		results = append(results, types.ProviderSearchResult{
			Title: source.Title, URL: source.URL, Snippet: source.Content, Source: "exa",
		})
	}
	return citations, results
}

func visibleWebSearchToolCalls(calls []types.ToolCall) []types.ToolCall {
	out := make([]types.ToolCall, 0, len(calls))
	for _, call := range calls {
		if call.Name != adapter.TrustedRouterWebSearchFunction {
			out = append(out, call)
		}
	}
	return out
}

func aggregateWebSearchStreamUsage(outcome responsesWebSearchOutcome) *adapter.StreamUsage {
	usage := &adapter.StreamUsage{
		InputTokens: outcome.InputTokens, OutputTokens: outcome.OutputTokens,
		CacheReadInputTokens: outcome.CachedTokens, ReasoningTokens: outcome.ReasoningTokens,
	}
	if outcome.Final.Result.Usage != nil {
		usage.CacheCreationInputTokens = outcome.Final.Result.Usage.CacheCreationInputTokens
		usage.ServiceTier = outcome.Final.Result.Usage.ServiceTier
		usage.InputExcludesCache = outcome.Final.Result.Usage.InputExcludesCache
	}
	return usage
}

type chatWebSearchEmitter struct {
	w         io.Writer
	requestID string
	model     string
	req       *types.OpenAIChatRequest
	created   int64
	text      strings.Builder
	writeErr  error
}

func newChatWebSearchEmitter(w io.Writer, requestID, model string, req *types.OpenAIChatRequest) *chatWebSearchEmitter {
	return &chatWebSearchEmitter{w: w, requestID: requestID, model: model, req: req, created: time.Now().Unix()}
}

func (emitter *chatWebSearchEmitter) Start() error {
	return writeFusionStreamDelta(emitter.w, emitter.requestID, emitter.model, emitter.created, map[string]any{"role": "assistant", "content": ""}, "")
}

func (emitter *chatWebSearchEmitter) SearchStarted(int, string, string) error {
	return emitter.writeErr
}
func (emitter *chatWebSearchEmitter) SearchCompleted(int, types.ResponseWebSearchCall) error {
	return emitter.writeErr
}

func (emitter *chatWebSearchEmitter) Observe(delta adapter.StreamDelta) {
	if emitter.writeErr != nil {
		return
	}
	switch delta.Type {
	case "text_delta":
		emitter.text.WriteString(delta.Text)
		emitter.writeErr = writeFusionStreamDelta(emitter.w, emitter.requestID, emitter.model, emitter.created, map[string]any{"content": delta.Text}, "")
	case "thinking_delta":
		emitter.writeErr = writeFusionStreamDelta(emitter.w, emitter.requestID, emitter.model, emitter.created, map[string]any{
			"reasoning": delta.Text, "reasoning_content": delta.Text,
		}, "")
	}
}

func (emitter *chatWebSearchEmitter) Replay(result adapter.StreamResult) {
	for _, thinking := range result.Thinking {
		emitter.Observe(adapter.StreamDelta{Type: "thinking_delta", Text: thinking.Text})
	}
	emitter.Observe(adapter.StreamDelta{Type: "text_delta", Text: result.Text})
}

func (emitter *chatWebSearchEmitter) Finish(outcome responsesWebSearchOutcome) error {
	if emitter.writeErr != nil {
		return emitter.writeErr
	}
	text, _ := ensureWebSearchCitations(outcome.Final.Result.Text, outcome.WebCalls, nil)
	if emitted := emitter.text.String(); strings.HasPrefix(text, emitted) {
		remaining := strings.TrimPrefix(text, emitted)
		if remaining != "" {
			emitter.Observe(adapter.StreamDelta{Type: "text_delta", Text: remaining})
		}
	} else if emitter.text.Len() == 0 {
		emitter.Observe(adapter.StreamDelta{Type: "text_delta", Text: text})
	}
	if emitter.writeErr != nil {
		return emitter.writeErr
	}
	citations, searchResults := chatWebSearchProvenance(outcome)
	if len(citations) > 0 || len(searchResults) > 0 {
		if err := adapter.WriteProviderProvenanceChunk(
			emitter.w, emitter.requestID, emitter.model, emitter.created, text, citations, searchResults,
		); err != nil {
			return err
		}
	}
	toolCalls := visibleWebSearchToolCalls(outcome.Final.Result.ToolCalls)
	if err := writeFusionStreamToolCalls(emitter.w, emitter.requestID, emitter.model, emitter.created, toolCalls); err != nil {
		return err
	}
	finishReason := outcome.Final.Result.FinishReason
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	}
	if finishReason == "" {
		finishReason = "stop"
	}
	if err := writeFusionStreamDelta(emitter.w, emitter.requestID, emitter.model, emitter.created, map[string]any{}, finishReason); err != nil {
		return err
	}
	aggregate := outcome.Final
	aggregate.InputTokens = outcome.InputTokens
	aggregate.OutputTokens = outcome.OutputTokens
	aggregate.Result.Usage = aggregateWebSearchStreamUsage(outcome)
	if chatIncludeUsage(emitter.req) {
		if err := writeFusionStreamUsage(
			emitter.w, emitter.requestID, emitter.model, emitter.created,
			aggregate, outcome.TotalCostMicrodollars, responsesWebSearchProviderUsage(outcome),
		); err != nil {
			return err
		}
	}
	_, err := emitter.w.Write([]byte("data: [DONE]\n\n"))
	return err
}

func (emitter *chatWebSearchEmitter) Fail(err error) error {
	status, message := upstreamErrorResponse(err)
	var adapterErr *adapter.AdapterError
	if asAdapterErr(err, &adapterErr) {
		status, message = adapterErr.Status, adapterErr.Message
	}
	payload := map[string]any{"error": map[string]any{
		"message": message, "type": "server_error", "code": "web_search_failed", "status": status,
	}}
	body, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		return marshalErr
	}
	if _, writeErr := fmt.Fprintf(emitter.w, "data: %s\n\ndata: [DONE]\n\n", body); writeErr != nil {
		return writeErr
	}
	return nil
}
