package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var mapReduceDefaultMapperModels = []string{"deepseek/deepseek-v4-flash", "minimax/minimax-m3"}
var mapReduceDefaultParallelModels = []string{"deepseek/deepseek-v4-flash", "cerebras/gpt-oss-120b"}

type selectorDecision struct {
	SelectedIndex int    `json:"selected_index"`
	Rationale     string `json:"rationale,omitempty"`
}

type mapReducePlan struct {
	Parts []mapReducePart `json:"parts"`
}

type mapReducePart struct {
	Title  string `json:"title"`
	Prompt string `json:"prompt"`
}

func fusionModeForRequest(model string, configured string) string {
	switch strings.ToLower(strings.TrimSpace(configured)) {
	case fusionModeSelector, "select_best":
		return fusionModeSelector
	case fusionModeMapReduce, "map_reduce", "map-reduce":
		return fusionModeMapReduce
	case fusionModeSynth, "synthesize", "fusion":
		return fusionModeSynth
	}
	switch strings.ToLower(strings.TrimSpace(model)) {
	case trustedRouterSelectorModel:
		return fusionModeSelector
	case trustedRouterMapReduceModel:
		return fusionModeMapReduce
	default:
		return fusionModeSynth
	}
}

func serveSelectorNonStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	selectorModels []string,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestLogID string,
) {
	requestStarted := time.Now()
	requestID := newRequestID()
	panel, err := runFusionPanel(ctx, br, req, config, trGateway, secretCache, bearer, requestID, requestLogID)
	if err != nil {
		writeFusionError(ctx, conn, trGateway, err)
		return
	}
	selected, selectorAttempts, decision, err := runSelectorDecision(ctx, br, req, config, selectorModels, panel, trGateway, secretCache, bearer, requestID, requestLogID)
	if err != nil {
		writeFusionError(ctx, conn, trGateway, err)
		return
	}
	totalIn, totalOut := fusionUsageTotals(panel, selectorAttempts)
	responseModel := selected.Model
	if responseModel == "" {
		responseModel = selectedRouteModel(selected, req.Model)
	}
	responseModel = requestOrchestrationResponseModel(req, responseModel)
	details := selectorResponseDetails(config, panel, selectorAttempts, selected, decision, responseModel)
	var body bytes.Buffer
	if err := writeFusionChatCompletionResponse(
		&body,
		requestID,
		responseModel,
		selected.Result.Text,
		adapter.JoinThinking(selected.Result.Thinking),
		selected.Result.ToolCalls,
		totalIn,
		totalOut,
		fusionAggregateStreamUsage(totalIn, totalOut, panel, selectorAttempts),
		time.Now().Unix(),
		selected.Result.FinishReason,
		details,
	); err != nil {
		writeError(conn, 500, "selector response encoding error")
		return
	}
	fmt.Fprintf(os.Stderr,
		"enclave.selector_complete request_log_id=%q request_id=%q mode=nonstream panel=%d selector_attempts=%d selected_model=%q elapsed_ms=%d\n",
		requestLogID, requestID, len(panel), len(selectorAttempts), responseModel, time.Since(requestStarted).Milliseconds(),
	)
	writeJSONResponse(conn, 200, body.Bytes())
	_ = originalInput
}

func serveSelectorStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	selectorModels []string,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestLogID string,
) {
	requestID := newRequestID()
	created := time.Now().Unix()
	if err := writeResponseHead(conn, 200, "text/event-stream"); err != nil {
		return
	}
	chunkW := newChunkedWriter(conn)
	defer chunkW.Close()
	statsW := newStreamStatsWriter(chunkW)
	_ = writeFusionStreamEvent(statsW, requestID, req.Model, created, map[string]any{
		"event":              "selector.started",
		"mode":               fusionModeSelector,
		"preset":             config.Preset,
		"selection_strategy": config.SelectionStrategy,
	})
	panel, err := runFusionPanel(ctx, br, req, config, trGateway, secretCache, bearer, requestID, requestLogID)
	if err != nil {
		_ = writeFusionStreamError(statsW, requestID, req.Model, created, err)
		return
	}
	selected, selectorAttempts, decision, err := runSelectorDecision(ctx, br, req, config, selectorModels, panel, trGateway, secretCache, bearer, requestID, requestLogID)
	if err != nil {
		_ = writeFusionStreamError(statsW, requestID, req.Model, created, err)
		return
	}
	_ = writeFusionStreamEvent(statsW, requestID, req.Model, created, map[string]any{
		"event":    "selector.done",
		"mode":     fusionModeSelector,
		"decision": decision,
		"selected": fusionCallDetails(selected),
	})
	responseModel := requestOrchestrationResponseModel(req, selected.Model)
	if selected.Result.Text != "" {
		_ = writeFusionStreamDelta(statsW, requestID, responseModel, created, map[string]any{"content": selected.Result.Text}, "")
	}
	if err := writeFusionStreamDelta(statsW, requestID, responseModel, created, map[string]any{}, selected.Result.FinishReason); err != nil {
		return
	}
	if chatIncludeUsage(req) {
		totalIn, totalOut := fusionUsageTotals(panel, selectorAttempts)
		selected.InputTokens = totalIn
		selected.OutputTokens = totalOut
		selected.Result.Usage = fusionAggregateStreamUsage(totalIn, totalOut, panel, selectorAttempts)
		details := selectorResponseDetails(config, panel, selectorAttempts, selected, decision, responseModel)
		_ = writeFusionStreamUsage(statsW, requestID, responseModel, created, selected, fusionTotalCostMicrodollars(panel, selectorAttempts), fusionProviderUsage(details))
	}
	_, _ = statsW.Write([]byte("data: [DONE]\n\n"))
	_ = originalInput
}

func runSelectorDecision(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	selectorModels []string,
	panel []fusionCallResult,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
) (fusionCallResult, []fusionCallResult, selectorDecision, error) {
	attempts := make([]fusionCallResult, 0, len(selectorModels))
	var lastErr error
	for i, model := range selectorModels {
		selectorReq := selectorRequest(req, model, panel, config)
		var parsed selectorDecision
		selector, err := runFusionCallValidated(
			ctx,
			br,
			selectorReq,
			trGateway,
			secretCache,
			bearer,
			"fusion.selector",
			fmt.Sprintf("%s:selector:%d", requestID, i),
			requestLogID,
			nil,
			false,
			func(result adapter.StreamResult) error {
				decision, err := parseSelectorDecision(result.Text, len(panel))
				if err != nil {
					return err
				}
				parsed = decision
				return nil
			},
			true,
		)
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr,
				"enclave.selector_failed request_log_id=%q request_id=%q model=%q attempt=%d error=%q\n",
				requestLogID, requestID, model, i+1, err.Error(),
			)
			if fusionCanTryNextModel(err) {
				continue
			}
			return fusionCallResult{}, attempts, selectorDecision{}, err
		}
		attempts = append(attempts, selector)
		selected := panel[parsed.SelectedIndex-1]
		if !fusionPanelResultUsable(selected) {
			lastErr = &fusionModelFallbackError{err: &adapter.AdapterError{Status: 502, Message: "trustedrouter/selector chose an unusable panel answer", Context: "selector.selected_index"}}
			continue
		}
		return selected, attempts, parsed, nil
	}
	if lastErr != nil {
		return fusionCallResult{}, attempts, selectorDecision{}, lastErr
	}
	return fusionCallResult{}, attempts, selectorDecision{}, &adapter.AdapterError{Status: 502, Message: "trustedrouter/selector produced no usable selection", Context: "fusion.selector"}
}

func selectorRequest(req *types.OpenAIChatRequest, model string, panel []fusionCallResult, config fusionConfig) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = model
	out.Models = nil
	forceFusionThroughputRouting(out)
	out.Stream = false
	out.Tools = nil
	out.ToolChoice = nil
	out.Plugins = nil
	out.ResponseFormat = map[string]any{"type": "json_object"}
	out.MaxTokens = fusionInnerMaxTokens(req, config.MaxCompletionTokens)
	instruction := "You are the TrustedRouter Selector. Choose the single best panel answer for the original user request. Return only JSON: {\"selected_index\": <1-based integer>, \"rationale\": \"brief reason\"}. Do not rewrite, summarize, or improve the selected answer."
	if custom := strings.TrimSpace(config.SelectorPrompt); custom != "" {
		instruction += "\n\nAdditional caller selector instructions:\n" + custom
	}
	out.Messages = []types.OpenAIChatMessage{
		{Role: "system", Content: instruction},
		{Role: "user", Content: fusionJudgePrompt(req, panel)},
	}
	out.Metadata = fusionMetadata(req.Metadata, "selector", model)
	return out
}

func normalizeMapReduceConfig(config *fusionConfig, requestedModel string) error {
	if config.MaxParts == 0 {
		config.MaxParts = defaultMapReduceParts
	}
	if config.MaxParts < 1 || config.MaxParts > maxMapReduceParts {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/mapreduce max_parts must be between 1 and 8", Context: "max_parts"}
	}
	mapperModels, err := normalizeComboModelList(config.MapperModels, mapReduceDefaultMapperModels, "mapper_models")
	if err != nil {
		return err
	}
	parallelFallback := mapReduceDefaultParallelModels
	if len(config.AnalysisModels) > 0 {
		parallelFallback = config.AnalysisModels
	}
	parallelModels, err := normalizeComboModelList(config.ParallelModels, parallelFallback, "parallel_models")
	if err != nil {
		return err
	}
	reducerFallback := config.FinalModels
	if len(reducerFallback) == 0 && config.JudgeModel != "" {
		reducerFallback = []string{config.JudgeModel}
	}
	if len(reducerFallback) == 0 && requestedModel != "" && !isFusionModel(requestedModel) {
		reducerFallback = []string{requestedModel}
	}
	if len(reducerFallback) == 0 {
		reducerFallback = fusionDefaultFinalModels
	}
	reducerModels, err := normalizeComboModelList(config.ReducerModels, reducerFallback, "reducer_models")
	if err != nil {
		return err
	}
	config.MapperModels = mapperModels
	config.ParallelModels = parallelModels
	config.ReducerModels = reducerModels
	return nil
}

func fusionSelectorModels(config fusionConfig) ([]string, error) {
	raw := config.SelectorModels
	if len(raw) == 0 {
		raw = config.JudgeModels
	}
	if len(raw) == 0 && config.JudgeModel != "" {
		raw = []string{config.JudgeModel}
	}
	if len(raw) == 0 {
		raw = fusionDefaultJudgeModels
	}
	return normalizeComboModelList(raw, nil, "selector_models")
}

func serveMapReduceNonStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestLogID string,
) {
	requestStarted := time.Now()
	requestID := newRequestID()
	result, details, err := runMapReduce(ctx, br, req, config, trGateway, secretCache, bearer, originalInput, requestID, requestLogID)
	if err != nil {
		writeFusionError(ctx, conn, trGateway, err)
		return
	}
	totalIn, totalOut := mapReduceUsageTotals(details)
	responseModel := requestOrchestrationResponseModel(req, result.Model)
	responseDetails := mapReduceResponseDetails(config, details, result, responseModel)
	var body bytes.Buffer
	if err := writeFusionChatCompletionResponse(
		&body,
		requestID,
		responseModel,
		result.Result.Text,
		adapter.JoinThinking(result.Result.Thinking),
		result.Result.ToolCalls,
		totalIn,
		totalOut,
		fusionAggregateStreamUsage(totalIn, totalOut, details.MapperAttempts, details.Parts, details.ReducerAttempts),
		time.Now().Unix(),
		result.Result.FinishReason,
		responseDetails,
	); err != nil {
		writeError(conn, 500, "mapreduce response encoding error")
		return
	}
	fmt.Fprintf(os.Stderr,
		"enclave.mapreduce_complete request_log_id=%q request_id=%q mode=nonstream parts=%d reducer_model=%q elapsed_ms=%d\n",
		requestLogID, requestID, len(details.Parts), result.Model, time.Since(requestStarted).Milliseconds(),
	)
	writeJSONResponse(conn, 200, body.Bytes())
}

func serveMapReduceStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestLogID string,
) {
	requestID := newRequestID()
	created := time.Now().Unix()
	if err := writeResponseHead(conn, 200, "text/event-stream"); err != nil {
		return
	}
	chunkW := newChunkedWriter(conn)
	defer chunkW.Close()
	statsW := newStreamStatsWriter(chunkW)
	_ = writeFusionStreamEvent(statsW, requestID, req.Model, created, map[string]any{
		"event":     "mapreduce.started",
		"mode":      fusionModeMapReduce,
		"max_parts": config.MaxParts,
	})
	result, details, err := runMapReduce(ctx, br, req, config, trGateway, secretCache, bearer, originalInput, requestID, requestLogID)
	if err != nil {
		_ = writeFusionStreamError(statsW, requestID, req.Model, created, err)
		return
	}
	_ = writeFusionStreamEvent(statsW, requestID, req.Model, created, map[string]any{
		"event":   "mapreduce.done",
		"mode":    fusionModeMapReduce,
		"details": mapReduceResponseDetails(config, details, result, requestOrchestrationResponseModel(req, result.Model)),
	})
	responseModel := requestOrchestrationResponseModel(req, result.Model)
	if result.Result.Text != "" {
		_ = writeFusionStreamDelta(statsW, requestID, responseModel, created, map[string]any{"content": result.Result.Text}, "")
	}
	if err := writeFusionStreamDelta(statsW, requestID, responseModel, created, map[string]any{}, result.Result.FinishReason); err != nil {
		return
	}
	if chatIncludeUsage(req) {
		totalIn, totalOut := mapReduceUsageTotals(details)
		result.InputTokens = totalIn
		result.OutputTokens = totalOut
		result.Result.Usage = fusionAggregateStreamUsage(totalIn, totalOut, details.MapperAttempts, details.Parts, details.ReducerAttempts)
		responseDetails := mapReduceResponseDetails(config, details, result, responseModel)
		_ = writeFusionStreamUsage(statsW, requestID, responseModel, created, result, mapReduceCostMicrodollars(details, result), fusionProviderUsage(responseDetails))
	}
	_, _ = statsW.Write([]byte("data: [DONE]\n\n"))
}

type mapReduceRunDetails struct {
	MapperAttempts  []fusionCallResult
	Plan            mapReducePlan
	Parts           []fusionCallResult
	ReducerAttempts []fusionCallResult
}

func runMapReduce(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestID string,
	requestLogID string,
) (fusionCallResult, mapReduceRunDetails, error) {
	_, mapperAttempts, plan, err := runMapReduceMapper(ctx, br, req, config, trGateway, secretCache, bearer, requestID, requestLogID)
	if err != nil {
		return fusionCallResult{}, mapReduceRunDetails{MapperAttempts: mapperAttempts}, err
	}
	parts, err := runMapReduceParts(ctx, br, req, config, plan, trGateway, secretCache, bearer, requestID, requestLogID)
	details := mapReduceRunDetails{MapperAttempts: mapperAttempts, Plan: plan, Parts: parts}
	if err != nil {
		return fusionCallResult{}, details, err
	}
	reducer, reducerAttempts, err := runMapReduceReducer(ctx, br, req, config, plan, parts, trGateway, secretCache, bearer, originalInput, requestID, requestLogID)
	details.ReducerAttempts = reducerAttempts
	if err != nil {
		return fusionCallResult{}, details, err
	}
	return reducer, details, nil
}

func runMapReduceMapper(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
) (fusionCallResult, []fusionCallResult, mapReducePlan, error) {
	attempts := make([]fusionCallResult, 0, len(config.MapperModels))
	var lastErr error
	for i, model := range config.MapperModels {
		mapperReq := mapReduceMapperRequest(req, model, config)
		var parsed mapReducePlan
		mapper, err := runFusionCallValidated(
			ctx,
			br,
			mapperReq,
			trGateway,
			secretCache,
			bearer,
			"fusion.mapreduce.mapper",
			fmt.Sprintf("%s:mapreduce:mapper:%d", requestID, i),
			requestLogID,
			nil,
			false,
			func(result adapter.StreamResult) error {
				plan, err := parseMapReducePlan(result.Text, config.MaxParts)
				if err != nil {
					return err
				}
				parsed = plan
				return nil
			},
			true,
		)
		if err != nil {
			lastErr = err
			if fusionCanTryNextModel(err) {
				continue
			}
			return fusionCallResult{}, attempts, mapReducePlan{}, err
		}
		attempts = append(attempts, mapper)
		return mapper, attempts, parsed, nil
	}
	if lastErr != nil {
		return fusionCallResult{}, attempts, mapReducePlan{}, lastErr
	}
	return fusionCallResult{}, attempts, mapReducePlan{}, &adapter.AdapterError{Status: 502, Message: "trustedrouter/mapreduce mapper produced no valid plan", Context: "fusion.mapreduce.mapper"}
}

func runMapReduceParts(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	plan mapReducePlan,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
) ([]fusionCallResult, error) {
	parts := make([]fusionCallResult, len(plan.Parts))
	errs := make([]error, len(plan.Parts))
	var wg sync.WaitGroup
	for i, part := range plan.Parts {
		wg.Add(1)
		go func(i int, part mapReducePart) {
			defer wg.Done()
			result, err := runMapReducePart(ctx, br, req, config, part, i, trGateway, secretCache, bearer, requestID, requestLogID)
			if err != nil {
				errs[i] = err
				parts[i] = fusionCallResult{
					Result: adapter.StreamResult{
						Text:         fmt.Sprintf("[mapreduce part %d failed before producing an answer: %s]", i+1, err.Error()),
						FinishReason: "error",
					},
					Model: config.ParallelModels[0],
				}
				return
			}
			parts[i] = result
		}(i, part)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return parts, err
		}
	}
	return parts, nil
}

func runMapReducePart(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	part mapReducePart,
	index int,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
) (fusionCallResult, error) {
	var lastErr error
	for i, model := range config.ParallelModels {
		partReq := mapReducePartRequest(req, model, part, index, config)
		partResult, err := runFusionCallValidated(
			ctx,
			br,
			partReq,
			trGateway,
			secretCache,
			bearer,
			"fusion.mapreduce.part",
			fmt.Sprintf("%s:mapreduce:part:%d:%d", requestID, index, i),
			requestLogID,
			nil,
			false,
			fusionValidateFinalResult,
			true,
		)
		if err != nil {
			lastErr = err
			if fusionCanTryNextModel(err) {
				continue
			}
			return fusionCallResult{}, err
		}
		return partResult, nil
	}
	if lastErr != nil {
		return fusionCallResult{}, lastErr
	}
	return fusionCallResult{}, &adapter.AdapterError{Status: 502, Message: "trustedrouter/mapreduce part produced no answer", Context: "fusion.mapreduce.part"}
}

func runMapReduceReducer(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	plan mapReducePlan,
	parts []fusionCallResult,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestID string,
	requestLogID string,
) (fusionCallResult, []fusionCallResult, error) {
	attempts := make([]fusionCallResult, 0, len(config.ReducerModels))
	var lastErr error
	for i, model := range config.ReducerModels {
		reducerReq := mapReduceReducerRequest(req, model, plan, parts, config)
		reducer, err := runFusionCallValidated(
			ctx,
			br,
			reducerReq,
			trGateway,
			secretCache,
			bearer,
			"fusion.mapreduce.reducer",
			fmt.Sprintf("%s:mapreduce:reducer:%d", requestID, i),
			requestLogID,
			originalInput,
			true,
			fusionValidateFinalResult,
			true,
		)
		if err != nil {
			lastErr = err
			if fusionCanTryNextModel(err) {
				continue
			}
			return fusionCallResult{}, attempts, err
		}
		attempts = append(attempts, reducer)
		return reducer, attempts, nil
	}
	if lastErr != nil {
		return fusionCallResult{}, attempts, lastErr
	}
	return fusionCallResult{}, attempts, &adapter.AdapterError{Status: 502, Message: "trustedrouter/mapreduce reducer produced no usable answer", Context: "fusion.mapreduce.reducer"}
}

func mapReduceMapperRequest(req *types.OpenAIChatRequest, model string, config fusionConfig) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = model
	out.Models = nil
	forceFusionThroughputRouting(out)
	out.Stream = false
	out.Tools = nil
	out.ToolChoice = nil
	out.Plugins = nil
	out.ResponseFormat = map[string]any{"type": "json_object"}
	out.MaxTokens = fusionInnerMaxTokens(req, config.MaxCompletionTokens)
	instruction := fmt.Sprintf("You are the TrustedRouter MapReduce mapper. Divide the original request into 1 to %d independent parts that can be answered in parallel. Return only JSON with shape {\"parts\":[{\"title\":\"short title\",\"prompt\":\"self-contained task for this part\"}]}. Do not solve the parts.", config.MaxParts)
	if custom := strings.TrimSpace(config.MapperPrompt); custom != "" {
		instruction += "\n\nAdditional caller mapper instructions:\n" + custom
	}
	out.Messages = []types.OpenAIChatMessage{
		{Role: "system", Content: instruction},
		{Role: "user", Content: chatMessagesText(req.Messages)},
	}
	out.Metadata = fusionMetadata(req.Metadata, "mapreduce.mapper", model)
	return out
}

func mapReducePartRequest(req *types.OpenAIChatRequest, model string, part mapReducePart, index int, config fusionConfig) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = model
	out.Models = nil
	forceFusionThroughputRouting(out)
	out.Stream = false
	out.Tools = stripFusionToolEntries(req.Tools)
	if len(out.Tools) == 0 {
		out.ToolChoice = nil
	}
	out.Plugins = nil
	out.ResponseFormat = nil
	out.MaxTokens = fusionInnerMaxTokens(req, config.MaxCompletionTokens)
	system := fmt.Sprintf("You are TrustedRouter MapReduce parallel worker %d. Solve only the assigned part. Return a self-contained answer for that part.", index+1)
	if len(out.Tools) > 0 {
		system += "\n\nIf the next correct step is a provided function call, emit the tool call directly instead of describing it."
	}
	if custom := strings.TrimSpace(config.ParallelPrompt); custom != "" {
		system += "\n\nAdditional caller parallel worker instructions:\n" + custom
	}
	out.Messages = append([]types.OpenAIChatMessage{{Role: "system", Content: system}}, req.Messages...)
	out.Messages = append(out.Messages, types.OpenAIChatMessage{
		Role:    "user",
		Content: fmt.Sprintf("Assigned MapReduce part %d:\nTitle: %s\nPrompt: %s", index+1, part.Title, part.Prompt),
	})
	out.Metadata = fusionMetadata(req.Metadata, "mapreduce.part", model)
	return out
}

func mapReduceReducerRequest(req *types.OpenAIChatRequest, model string, plan mapReducePlan, parts []fusionCallResult, config fusionConfig) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = model
	out.Models = nil
	forceFusionThroughputRouting(out)
	out.Stream = false
	out.Tools = stripFusionToolEntries(req.Tools)
	if len(out.Tools) == 0 {
		out.ToolChoice = nil
	}
	out.Plugins = nil
	out.ResponseFormat = req.ResponseFormat
	out.MaxTokens = fusionInnerMaxTokens(req, config.MaxCompletionTokens)
	instruction := "You are the TrustedRouter MapReduce reducer. Combine the parallel part answers into one coherent final answer for the original request. Preserve correctness, remove duplication, and do not mention internal orchestration unless the user asked."
	if len(out.Tools) > 0 {
		instruction += "\n\nIf the next correct action is a provided function call, emit the tool call directly instead of describing it in text. Return visible text only when no tool call is needed."
	}
	if custom := strings.TrimSpace(config.ReducerPrompt); custom != "" {
		instruction += "\n\nAdditional caller reducer instructions:\n" + custom
	} else if custom := strings.TrimSpace(config.SynthesisPrompt); custom != "" {
		instruction += "\n\nAdditional caller reducer instructions:\n" + custom
	}
	out.Messages = append([]types.OpenAIChatMessage{}, req.Messages...)
	out.Messages = append(out.Messages, types.OpenAIChatMessage{
		Role:    "user",
		Content: instruction + "\n\n" + mapReduceEvidence(plan, parts),
	})
	out.Metadata = fusionMetadata(req.Metadata, "mapreduce.reducer", model)
	return out
}

func parseSelectorDecision(text string, panelLen int) (selectorDecision, error) {
	var decision selectorDecision
	if panelLen < 1 {
		return decision, &adapter.AdapterError{Status: 502, Message: "trustedrouter/selector has no panel answers to select", Context: "selector.panel"}
	}
	if err := json.Unmarshal([]byte(extractJSONObject(text)), &decision); err != nil {
		return decision, &fusionModelFallbackError{err: &adapter.AdapterError{Status: 502, Message: "trustedrouter/selector returned invalid JSON", Context: "selector.selected_index"}}
	}
	if decision.SelectedIndex < 1 || decision.SelectedIndex > panelLen {
		return decision, &fusionModelFallbackError{err: &adapter.AdapterError{Status: 502, Message: "trustedrouter/selector selected_index is out of range", Context: "selector.selected_index"}}
	}
	return decision, nil
}

func parseMapReducePlan(text string, maxParts int) (mapReducePlan, error) {
	var plan mapReducePlan
	if err := json.Unmarshal([]byte(extractJSONObject(text)), &plan); err != nil {
		return plan, &fusionModelFallbackError{err: &adapter.AdapterError{Status: 502, Message: "trustedrouter/mapreduce mapper returned invalid JSON", Context: "mapreduce.parts"}}
	}
	if len(plan.Parts) < 1 || len(plan.Parts) > maxParts || len(plan.Parts) > maxMapReduceParts {
		return plan, &fusionModelFallbackError{err: &adapter.AdapterError{Status: 502, Message: "trustedrouter/mapreduce mapper returned an invalid number of parts", Context: "mapreduce.parts"}}
	}
	for i := range plan.Parts {
		plan.Parts[i].Title = strings.TrimSpace(plan.Parts[i].Title)
		plan.Parts[i].Prompt = strings.TrimSpace(plan.Parts[i].Prompt)
		if plan.Parts[i].Prompt == "" {
			return plan, &fusionModelFallbackError{err: &adapter.AdapterError{Status: 502, Message: "trustedrouter/mapreduce mapper returned an empty part prompt", Context: "mapreduce.parts"}}
		}
		if plan.Parts[i].Title == "" {
			plan.Parts[i].Title = fmt.Sprintf("Part %d", i+1)
		}
	}
	return plan, nil
}

func extractJSONObject(text string) string {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "```") {
		lines := strings.Split(trimmed, "\n")
		if len(lines) >= 3 {
			trimmed = strings.TrimSpace(strings.Join(lines[1:len(lines)-1], "\n"))
		}
	}
	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start >= 0 && end >= start {
		return trimmed[start : end+1]
	}
	return trimmed
}

func normalizeComboModelList(raw []string, fallback []string, context string) ([]string, error) {
	if len(raw) == 0 {
		raw = fallback
	}
	if len(raw) == 0 || len(raw) > 8 {
		return nil, &adapter.AdapterError{Status: 400, Message: "trustedrouter combo model lists must contain 1-8 models", Context: context}
	}
	out := make([]string, 0, len(raw))
	for _, model := range raw {
		resolved := resolveFusionModelID(model)
		if resolved == "" {
			return nil, &adapter.AdapterError{Status: 400, Message: "trustedrouter combo model ids must be non-empty strings", Context: context}
		}
		out = append(out, resolved)
	}
	return out, nil
}

func selectorResponseDetails(config fusionConfig, panel []fusionCallResult, selectorAttempts []fusionCallResult, selected fusionCallResult, decision selectorDecision, routerModel string) map[string]any {
	details := map[string]any{
		"router":             routerModel,
		"primitive":          trustedRouterSelectorModel,
		"mode":               fusionModeSelector,
		"preset":             config.Preset,
		"selection_strategy": fusionSelectorSelectionStrategy,
		"selected_model":     selected.Model,
		"selected_index":     decision.SelectedIndex,
		"panel":              fusionCallDetailsList(panel),
		"selector_attempts":  fusionCallDetailsList(selectorAttempts),
		"note":               "Selector returns the chosen panel answer verbatim; selector_attempts contain only decision metadata.",
	}
	if cost := fusionTotalCostMicrodollars(panel, selectorAttempts); cost > 0 {
		details["cost_microdollars"] = cost
	}
	return details
}

func mapReduceResponseDetails(config fusionConfig, details mapReduceRunDetails, reducer fusionCallResult, routerModel string) map[string]any {
	out := map[string]any{
		"router":             routerModel,
		"primitive":          trustedRouterMapReduceModel,
		"mode":               fusionModeMapReduce,
		"preset":             config.Preset,
		"selection_strategy": fusionModeMapReduce,
		"selected_model":     reducer.Model,
		"mapper_attempts":    fusionCallDetailsList(details.MapperAttempts),
		"parts":              mapReducePartDetails(details.Plan, details.Parts),
		"reducer_attempts":   fusionCallDetailsList(details.ReducerAttempts),
		"note":               "MapReduce mapper, parallel workers, and reducer are billed as separate internal calls.",
	}
	if cost := mapReduceCostMicrodollars(details, reducer); cost > 0 {
		out["cost_microdollars"] = cost
	}
	return out
}

func mapReducePartDetails(plan mapReducePlan, parts []fusionCallResult) []map[string]any {
	out := make([]map[string]any, 0, len(parts))
	for i, part := range parts {
		item := fusionCallDetails(part)
		if i < len(plan.Parts) {
			item["title"] = plan.Parts[i].Title
		}
		out = append(out, item)
	}
	return out
}

func mapReduceEvidence(plan mapReducePlan, parts []fusionCallResult) string {
	var b strings.Builder
	b.WriteString("MapReduce part answers:\n")
	for i, item := range parts {
		title := fmt.Sprintf("Part %d", i+1)
		prompt := ""
		if i < len(plan.Parts) {
			title = plan.Parts[i].Title
			prompt = plan.Parts[i].Prompt
		}
		model := item.Model
		if model == "" && item.Authorization != nil {
			model = item.Authorization.Model
		}
		fmt.Fprintf(&b, "\n[%d] title=%s model=%s\nAssigned prompt:\n%s\nAnswer:\n%s\n", i+1, title, model, prompt, strings.TrimSpace(item.Result.Text))
	}
	return b.String()
}

func mapReduceUsageTotals(details mapReduceRunDetails) (int, int) {
	inputs, outputs := fusionUsageTotals(details.Parts, details.MapperAttempts, details.ReducerAttempts...)
	return inputs, outputs
}

func mapReduceCostMicrodollars(details mapReduceRunDetails, reducer fusionCallResult) int {
	_ = reducer
	return fusionTotalCostMicrodollars(details.MapperAttempts, details.Parts, details.ReducerAttempts)
}
