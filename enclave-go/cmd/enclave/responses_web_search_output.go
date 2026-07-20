package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func serveResponsesWebSearchJSON(
	conn io.Writer,
	responseID string,
	model string,
	req *types.OpenAIChatRequest,
	outcome responsesWebSearchOutcome,
) {
	text, annotations := ensureWebSearchCitations(outcome.Final.Result.Text, outcome.WebCalls, responseTextConfig(req))
	req.Response.WebSearchCalls = outcome.WebCalls
	req.Response.OutputAnnotations = annotations
	var body bytes.Buffer
	if err := adapter.WriteResponsesResponse(
		&body,
		responseID,
		model,
		text,
		outcome.Final.Result.ToolCalls,
		outcome.InputTokens,
		outcome.OutputTokens,
		nil,
		time.Now().Unix(),
		responseTextConfig(req),
		req.Response,
	); err != nil {
		writeOpenAIError(conn, 500, "responses encoding error", "server_error", "internal_error", "")
		return
	}
	annotated, err := annotateResponsesWebSearchUsage(body.Bytes(), outcome)
	if err != nil {
		writeOpenAIError(conn, 500, "responses encoding error", "server_error", "internal_error", "")
		return
	}
	writeJSONResponse(conn, http.StatusOK, annotated)
}

func annotateResponsesWebSearchUsage(body []byte, outcome responsesWebSearchOutcome) ([]byte, error) {
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
	totalCost := outcome.TotalCostMicrodollars
	usage["cost_microdollars"] = totalCost
	usage["total_cost_microdollars"] = totalCost
	usage["provider_usage"] = providerUsage
	applyUsageProviderSummary(usage, providerUsage)
	payload["trustedrouter"] = map[string]any{"routing": providerUsage}
	return json.Marshal(payload)
}

func responsesWebSearchProviderUsage(outcome responsesWebSearchOutcome) map[string]any {
	modelCalls := make([]map[string]any, 0, len(outcome.ModelCalls))
	for _, call := range outcome.ModelCalls {
		modelCalls = append(modelCalls, providerUsageCall(fusionCallDetails(call), "web_search"))
	}
	totalCost := outcome.TotalCostMicrodollars
	return pruneEmptyProviderUsage(map[string]any{
		"orchestration":                         true,
		"router":                                "web_search",
		"subcall_count":                         len(modelCalls),
		"web_search_call_count":                 len(outcome.WebCalls),
		"model_attempts":                        modelCalls,
		"cost_microdollars":                     totalCost,
		"total_cost_microdollars":               totalCost,
		"web_search_cost_microdollars":          outcome.SearchCostMicrodollars,
		"operator_web_search_cost_microdollars": outcome.SearchCostMicrodollars,
		"web_search_elapsed_ms":                 outcome.SearchElapsedMS,
		"contains_prompt_or_completion":         false,
	})
}

func logResponsesWebSearchEnd(requestLogID string, started time.Time, outcome responsesWebSearchOutcome, err error) {
	status := "ok"
	errorType := ""
	if err != nil {
		status = "error"
		errorType = fmt.Sprintf("%T", err)
	}
	fmt.Fprintf(os.Stderr,
		"enclave.responses_web_search_end request_log_id=%q outcome=%q error_type=%q web_calls=%d model_calls=%d search_elapsed_ms=%d elapsed_ms=%d\n",
		requestLogID, status, errorType, len(outcome.WebCalls), len(outcome.ModelCalls), outcome.SearchElapsedMS, time.Since(started).Milliseconds(),
	)
}

func ensureWebSearchCitations(
	text string,
	calls []types.ResponseWebSearchCall,
	textConfig map[string]any,
) (string, []map[string]any) {
	if len(calls) == 0 {
		return text, nil
	}
	formatType := ""
	if format, ok := textConfig["format"].(map[string]any); ok {
		formatType, _ = format["type"].(string)
	}
	sources := uniqueWebSearchSources(calls)
	if formatType != "json_object" && formatType != "json_schema" && !containsWebSearchSourceURL(text, sources) && len(sources) > 0 {
		var appendix strings.Builder
		appendix.WriteString("\n\nSources:\n")
		for _, source := range sources {
			appendix.WriteString("- [")
			appendix.WriteString(markdownLinkTitle(source.Title))
			appendix.WriteString("](")
			appendix.WriteString(source.URL)
			appendix.WriteString(")\n")
		}
		text += strings.TrimSuffix(appendix.String(), "\n")
	}
	annotations := []map[string]any{}
	for _, source := range sources {
		from := 0
		for {
			relative := strings.Index(text[from:], source.URL)
			if relative < 0 {
				break
			}
			startByte := from + relative
			endByte := startByte + len(source.URL)
			annotations = append(annotations, map[string]any{
				"type":        "url_citation",
				"start_index": utf8.RuneCountInString(text[:startByte]),
				"end_index":   utf8.RuneCountInString(text[:endByte]),
				"url":         source.URL,
				"title":       source.Title,
			})
			from = endByte
		}
	}
	sort.SliceStable(annotations, func(i, j int) bool {
		return providerUsageInt(annotations[i]["start_index"]) < providerUsageInt(annotations[j]["start_index"])
	})
	return text, annotations
}

func uniqueWebSearchSources(calls []types.ResponseWebSearchCall) []types.ResponseWebSearchSource {
	seen := map[string]struct{}{}
	out := []types.ResponseWebSearchSource{}
	for _, call := range calls {
		for _, source := range call.Sources {
			if source.URL == "" {
				continue
			}
			if _, ok := seen[source.URL]; ok {
				continue
			}
			seen[source.URL] = struct{}{}
			out = append(out, source)
			if len(out) >= 10 {
				return out
			}
		}
	}
	return out
}

func containsWebSearchSourceURL(text string, sources []types.ResponseWebSearchSource) bool {
	for _, source := range sources {
		if strings.Contains(text, source.URL) {
			return true
		}
	}
	return false
}

func markdownLinkTitle(title string) string {
	title = strings.NewReplacer("[", "\\[", "]", "\\]", "\n", " ", "\r", " ").Replace(strings.TrimSpace(title))
	if title == "" {
		return "Source"
	}
	return title
}

type responsesWebSearchEmitter struct {
	w          io.Writer
	responseID string
	model      string
	req        *types.OpenAIChatRequest
	created    int64
	sequence   int
	messageID  string
	messageIdx int
	messageOn  bool
	reasonID   string
	reasonIdx  int
	reasonOn   bool
	text       strings.Builder
	reasoning  strings.Builder
	nextIndex  int
}

func newResponsesWebSearchEmitter(w io.Writer, responseID, model string, req *types.OpenAIChatRequest) *responsesWebSearchEmitter {
	return &responsesWebSearchEmitter{
		w:          w,
		responseID: responseID,
		model:      model,
		req:        req,
		created:    time.Now().Unix(),
		messageID:  "msg_" + strings.TrimPrefix(responseID, "resp_"),
		reasonID:   "rs_" + strings.TrimPrefix(responseID, "resp_"),
	}
}

func (emitter *responsesWebSearchEmitter) Start() error {
	for _, event := range []string{"response.created", "response.in_progress"} {
		if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, event, map[string]any{
			"type": event,
			"response": adapter.BuildResponsesObject(
				emitter.responseID, emitter.model, "", nil, 0, 0, 0, 0,
				emitter.created, "in_progress", responseTextConfig(emitter.req), emitter.req.Response,
			),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (emitter *responsesWebSearchEmitter) SearchStarted(index int, callID, query string) error {
	itemID := webSearchStreamID(callID, index)
	outputIndex := emitter.nextIndex
	emitter.nextIndex++
	if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.output_item.added", map[string]any{
		"type": "response.output_item.added", "output_index": outputIndex,
		"item": map[string]any{"id": itemID, "type": "web_search_call", "status": "in_progress", "action": map[string]any{"type": "search", "query": query}},
	}); err != nil {
		return err
	}
	for _, event := range []string{"response.web_search_call.in_progress", "response.web_search_call.searching"} {
		if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, event, map[string]any{
			"type": event, "item_id": itemID, "output_index": outputIndex,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (emitter *responsesWebSearchEmitter) SearchCompleted(index int, call types.ResponseWebSearchCall) error {
	outputIndex := index
	itemID := webSearchStreamID(call.ID, index)
	if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.web_search_call.completed", map[string]any{
		"type": "response.web_search_call.completed", "item_id": itemID, "output_index": outputIndex,
	}); err != nil {
		return err
	}
	return adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.output_item.done", map[string]any{
		"type": "response.output_item.done", "output_index": outputIndex,
		"item": adapter.ResponseWebSearchCallItem(call, emitter.req.Response.WebSearch.IncludeSources),
	})
}

func webSearchStreamID(callID string, index int) string {
	if strings.HasPrefix(callID, "ws_") {
		return callID
	}
	return fmt.Sprintf("ws_stream_%d", index)
}

func (emitter *responsesWebSearchEmitter) Observe(delta adapter.StreamDelta) {
	var err error
	switch delta.Type {
	case "text_delta":
		err = emitter.emitText(delta.Text)
	case "thinking_delta":
		err = emitter.emitReasoning(delta.Text)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.responses_web_search_emit_failed err=%v\n", err)
	}
}

func (emitter *responsesWebSearchEmitter) Replay(result adapter.StreamResult) {
	for _, thinking := range result.Thinking {
		_ = emitter.emitReasoning(thinking.Text)
	}
	_ = emitter.emitText(result.Text)
}

func (emitter *responsesWebSearchEmitter) startMessage() error {
	if emitter.messageOn {
		return nil
	}
	emitter.messageOn = true
	emitter.messageIdx = emitter.nextIndex
	emitter.nextIndex++
	if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.output_item.added", map[string]any{
		"type": "response.output_item.added", "output_index": emitter.messageIdx,
		"item": map[string]any{"id": emitter.messageID, "type": "message", "status": "in_progress", "role": "assistant", "content": []any{}},
	}); err != nil {
		return err
	}
	return adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.content_part.added", map[string]any{
		"type": "response.content_part.added", "item_id": emitter.messageID,
		"output_index": emitter.messageIdx, "content_index": 0,
		"part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}},
	})
}

func (emitter *responsesWebSearchEmitter) emitText(text string) error {
	if text == "" {
		return nil
	}
	if err := emitter.startMessage(); err != nil {
		return err
	}
	emitter.text.WriteString(text)
	return adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.output_text.delta", map[string]any{
		"type": "response.output_text.delta", "item_id": emitter.messageID,
		"output_index": emitter.messageIdx, "content_index": 0, "delta": text,
	})
}

func (emitter *responsesWebSearchEmitter) startReasoning() error {
	if emitter.reasonOn {
		return nil
	}
	emitter.reasonOn = true
	emitter.reasonIdx = emitter.nextIndex
	emitter.nextIndex++
	if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.output_item.added", map[string]any{
		"type": "response.output_item.added", "output_index": emitter.reasonIdx,
		"item": map[string]any{"id": emitter.reasonID, "type": "reasoning", "status": "in_progress", "summary": []any{}},
	}); err != nil {
		return err
	}
	return adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.content_part.added", map[string]any{
		"type": "response.content_part.added", "item_id": emitter.reasonID,
		"output_index": emitter.reasonIdx, "content_index": 0,
		"part": map[string]any{"type": "reasoning_text", "text": ""},
	})
}

func (emitter *responsesWebSearchEmitter) emitReasoning(text string) error {
	if text == "" {
		return nil
	}
	if err := emitter.startReasoning(); err != nil {
		return err
	}
	emitter.reasoning.WriteString(text)
	return adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.reasoning_text.delta", map[string]any{
		"type": "response.reasoning_text.delta", "item_id": emitter.reasonID,
		"output_index": emitter.reasonIdx, "content_index": 0, "delta": text,
	})
}

func (emitter *responsesWebSearchEmitter) Finish(outcome responsesWebSearchOutcome) error {
	text, annotations := ensureWebSearchCitations(outcome.Final.Result.Text, outcome.WebCalls, responseTextConfig(emitter.req))
	if emitted := emitter.text.String(); strings.HasPrefix(text, emitted) {
		if err := emitter.emitText(strings.TrimPrefix(text, emitted)); err != nil {
			return err
		}
	} else if emitted == "" {
		if err := emitter.emitText(text); err != nil {
			return err
		}
	}
	if emitter.reasonOn {
		if err := emitter.finishReasoning(); err != nil {
			return err
		}
	}
	if emitter.messageOn {
		if err := emitter.finishMessage(text, annotations); err != nil {
			return err
		}
	}
	for _, call := range outcome.Final.Result.ToolCalls {
		if call.Name == adapter.TrustedRouterWebSearchFunction {
			continue
		}
		outputIndex := emitter.nextIndex
		emitter.nextIndex++
		item := responseFunctionCallStreamingItem(emitter.responseID, outputIndex, call)
		if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.output_item.added", map[string]any{
			"type": "response.output_item.added", "output_index": outputIndex, "item": item,
		}); err != nil {
			return err
		}
		if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.output_item.done", map[string]any{
			"type": "response.output_item.done", "output_index": outputIndex, "item": item,
		}); err != nil {
			return err
		}
	}
	emitter.req.Response.WebSearchCalls = outcome.WebCalls
	emitter.req.Response.OutputAnnotations = annotations
	completed := adapter.BuildResponsesObject(
		emitter.responseID, emitter.model, text, outcome.Final.Result.ToolCalls,
		outcome.InputTokens, outcome.OutputTokens, outcome.CachedTokens, outcome.ReasoningTokens,
		emitter.created, "completed", responseTextConfig(emitter.req), emitter.req.Response,
	)
	annotateResponsesWebSearchObject(completed, outcome)
	if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.completed", map[string]any{
		"type": "response.completed", "response": completed,
	}); err != nil {
		return err
	}
	_, err := emitter.w.Write([]byte("data: [DONE]\n\n"))
	return err
}

func (emitter *responsesWebSearchEmitter) finishReasoning() error {
	text := emitter.reasoning.String()
	if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.reasoning_text.done", map[string]any{
		"type": "response.reasoning_text.done", "item_id": emitter.reasonID,
		"output_index": emitter.reasonIdx, "content_index": 0, "text": text,
	}); err != nil {
		return err
	}
	return adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.output_item.done", map[string]any{
		"type": "response.output_item.done", "output_index": emitter.reasonIdx,
		"item": map[string]any{"id": emitter.reasonID, "type": "reasoning", "status": "completed", "summary": []map[string]any{{"type": "reasoning_text", "text": text}}},
	})
}

func (emitter *responsesWebSearchEmitter) finishMessage(text string, annotations []map[string]any) error {
	if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.output_text.done", map[string]any{
		"type": "response.output_text.done", "item_id": emitter.messageID,
		"output_index": emitter.messageIdx, "content_index": 0, "text": text,
	}); err != nil {
		return err
	}
	if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.content_part.done", map[string]any{
		"type": "response.content_part.done", "item_id": emitter.messageID,
		"output_index": emitter.messageIdx, "content_index": 0,
		"part": map[string]any{"type": "output_text", "text": text, "annotations": annotations},
	}); err != nil {
		return err
	}
	return adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.output_item.done", map[string]any{
		"type": "response.output_item.done", "output_index": emitter.messageIdx,
		"item": map[string]any{"id": emitter.messageID, "type": "message", "status": "completed", "role": "assistant", "content": []map[string]any{{"type": "output_text", "text": text, "annotations": annotations}}},
	})
}

func responseFunctionCallStreamingItem(responseID string, index int, call types.ToolCall) map[string]any {
	id := call.ID
	if id == "" {
		id = fmt.Sprintf("fc_%s_%d", strings.TrimPrefix(responseID, "resp_"), index)
	}
	callID := call.CallID
	if callID == "" {
		callID = id
	}
	return map[string]any{"id": id, "type": "function_call", "status": "completed", "call_id": callID, "name": call.Name, "arguments": call.Arguments}
}

func annotateResponsesWebSearchObject(payload map[string]any, outcome responsesWebSearchOutcome) {
	usage, _ := payload["usage"].(map[string]any)
	if usage == nil {
		return
	}
	providerUsage := responsesWebSearchProviderUsage(outcome)
	totalCost := outcome.TotalCostMicrodollars
	usage["cost_microdollars"] = totalCost
	usage["total_cost_microdollars"] = totalCost
	usage["provider_usage"] = providerUsage
	applyUsageProviderSummary(usage, providerUsage)
	payload["trustedrouter"] = map[string]any{"routing": providerUsage}
}

func (emitter *responsesWebSearchEmitter) Fail(err error) error {
	status, message := upstreamErrorResponse(err)
	var adapterErr *adapter.AdapterError
	if errors.As(err, &adapterErr) {
		status, message = adapterErr.Status, adapterErr.Message
	}
	failed := adapter.BuildResponsesObject(
		emitter.responseID, emitter.model, "", nil, 0, 0, 0, 0,
		emitter.created, "failed", responseTextConfig(emitter.req), emitter.req.Response,
	)
	failed["error"] = map[string]any{"code": "web_search_failed", "message": message, "type": "server_error", "status": status}
	if err := adapter.WriteResponsesEvent(emitter.w, &emitter.sequence, "response.failed", map[string]any{
		"type": "response.failed", "response": failed,
	}); err != nil {
		return err
	}
	_, writeErr := emitter.w.Write([]byte("data: [DONE]\n\n"))
	return writeErr
}
