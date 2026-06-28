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

const trustedRouterSocrates10Model = "trustedrouter/socrates-1.0"
const trustedRouterSocratesModel = "trustedrouter/socrates"
const trustedRouterAdvisorModel = "trustedrouter/advisor"
const trustedRouterAdvisorTool = "trustedrouter:advisor"
const socratesAdviceToolName = "_trustedrouter_get_advice"

const defaultOrchestrationDepth = 2
const maxOrchestrationDepth = 4
const defaultSocratesAdviceCalls = 1
const maxSocratesAdviceCalls = 3
const defaultSocratesAdvisorMaxTokens = 4096
const maxSocratesAdvisorMaxTokens = 8192
const defaultSocratesAdvisorTimeoutMS = 90000
const maxSocratesAdvisorTimeoutMS = 180000

var defaultSocratesWorkerModels = []string{
	"cerebras/gpt-oss-120b",
	"deepseek/deepseek-v4-flash",
}

var defaultSocratesAdvisorModels = []string{
	"anthropic/claude-opus-4.8",
}

const fallbackSocratesWorkerPrompt = `You are TrustedRouter Socrates 1.0.

You have access to one private advisor tool: _trustedrouter_get_advice.

This tool is expensive and should be used rarely, roughly only when you are stuck, uncertain, or facing a high-stakes decision. Most requests should be completed without using it.

Do not call the advisor for straightforward work:
- simple factual answers
- obvious code edits
- routine summarization or formatting
- tasks where the next step is clear
- cases where you can answer confidently from the conversation

Call the advisor only when one of these is true:
- you are genuinely unsure between multiple approaches
- the task has security, privacy, legal, compliance, billing, or production-risk implications
- your first approach appears to be failing
- the user's constraints conflict or are underspecified in a way that affects correctness
- a wrong answer would be costly and a second opinion would materially improve the result

If you call the advisor, use its advice once, then continue and answer directly. Do not repeatedly ask for reassurance.`

const fallbackSocratesAdvisorPrompt = `You are the private TrustedRouter Socrates advisor.

Review the conversation and give concise, generous, actionable guidance to the worker model. Do not answer the user directly. Point out risks, missing constraints, likely mistakes, and a better approach. Keep the advice focused enough for the worker to act on immediately.`

type socratesConfig struct {
	Enabled              bool
	Depth                int
	DepthSet             bool
	WorkerModels         []string
	AdvisorModels        []string
	MaxAdviceCalls       int
	AdvisorMaxTokens     int
	AdvisorTimeoutMS     int
	BuiltInWorkerPrompt  string
	BuiltInAdvisorPrompt string
}

type socratesPromptBundle struct {
	Worker  string
	Advisor string
}

var socratesPromptMu sync.RWMutex
var socratesPromptCache socratesPromptBundle

func configureSocratesPrompts(boot *types.BootstrapData) {
	if boot == nil {
		return
	}
	socratesPromptMu.Lock()
	defer socratesPromptMu.Unlock()
	socratesPromptCache = socratesPromptBundle{
		Worker:  strings.TrimSpace(boot.SocratesWorkerPrompt),
		Advisor: strings.TrimSpace(boot.SocratesAdvisorPrompt),
	}
}

func isSocratesModel(model string) bool {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case trustedRouterSocrates10Model, trustedRouterSocratesModel, trustedRouterAdvisorModel:
		return true
	default:
		return false
	}
}

func isOrchestrationModel(model string) bool {
	return isSocratesModel(model) || isFusionModel(model)
}

func maybeServeSocrates(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestLogID string,
) (bool, error) {
	config, requested, err := socratesConfigForRequest(req)
	if err != nil {
		return true, err
	}
	if !requested {
		return false, nil
	}
	if !config.Enabled {
		if isSocratesModel(req.Model) {
			return true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/socrates cannot be disabled without selecting a concrete model", Context: "trustedrouter:advisor.enabled"}
		}
		return false, nil
	}
	if trGateway == nil || !trGateway.Enabled() {
		return true, &adapter.AdapterError{Status: 503, Message: "trustedrouter/socrates requires the TrustedRouter control plane", Context: "trustedrouter/socrates"}
	}
	if err := normalizeSocratesConfig(&config, req); err != nil {
		return true, err
	}
	if err := rejectSocratesToolCollision(req.Tools, req.ToolChoice); err != nil {
		return true, err
	}
	config.BuiltInWorkerPrompt, config.BuiltInAdvisorPrompt = socratesBuiltInPrompts()
	if socratesPromptsRequired() && (config.BuiltInWorkerPrompt == "" || config.BuiltInAdvisorPrompt == "") {
		return true, &adapter.AdapterError{Status: 503, Message: "trustedrouter/socrates prompt secrets are not configured", Context: "trustedrouter/socrates.prompts"}
	}
	if config.BuiltInWorkerPrompt == "" {
		config.BuiltInWorkerPrompt = fallbackSocratesWorkerPrompt
	}
	if config.BuiltInAdvisorPrompt == "" {
		config.BuiltInAdvisorPrompt = fallbackSocratesAdvisorPrompt
	}

	fmt.Fprintf(os.Stderr,
		"socrates.request_start request_log_id=%q model=%q depth_initial=%d max_get_advice_calls=%d worker_models=%q advisor_models=%q\n",
		requestLogID, req.Model, config.Depth, config.MaxAdviceCalls, strings.Join(config.WorkerModels, ","), strings.Join(config.AdvisorModels, ","),
	)
	if req.Stream {
		serveSocratesStreaming(ctx, conn, br, req, config, trGateway, secretCache, bearer, originalInput, requestLogID)
	} else {
		serveSocratesNonStreaming(ctx, conn, br, req, config, trGateway, secretCache, bearer, originalInput, requestLogID)
	}
	return true, nil
}

func socratesConfigForRequest(req *types.OpenAIChatRequest) (socratesConfig, bool, error) {
	config := socratesConfig{Enabled: true}
	requested := isSocratesModel(req.Model)
	if req.Depth != nil {
		config.Depth = *req.Depth
		config.DepthSet = true
	}
	cleanTools, toolConfig, toolRequested, err := socratesConfigFromTools(req.Tools)
	if err != nil {
		return socratesConfig{}, true, err
	}
	if toolRequested {
		config = mergeSocratesConfig(config, toolConfig)
		requested = true
		req.Tools = cleanTools
	}
	return config, requested, nil
}

func socratesConfigFromTools(tools []any) ([]any, socratesConfig, bool, error) {
	if len(tools) == 0 {
		return tools, socratesConfig{}, false, nil
	}
	clean := make([]any, 0, len(tools))
	config := socratesConfig{Enabled: true}
	var requested bool
	for _, item := range tools {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, socratesConfig{}, false, &adapter.AdapterError{Status: 400, Message: "tool must be an object", Context: "tools"}
		}
		toolType := strings.TrimSpace(stringValue(m["type"]))
		if strings.ToLower(toolType) != trustedRouterAdvisorTool {
			clean = append(clean, item)
			continue
		}
		params, err := fusionParametersMap(m["parameters"], "tools.parameters")
		if err != nil {
			return nil, socratesConfig{}, true, err
		}
		parsed, err := parseSocratesParameters(params)
		if err != nil {
			return nil, socratesConfig{}, true, err
		}
		config = mergeSocratesConfig(config, parsed)
		requested = true
	}
	return clean, config, requested, nil
}

func parseSocratesParameters(raw map[string]any) (socratesConfig, error) {
	config := socratesConfig{Enabled: true}
	if raw == nil {
		return config, nil
	}
	if enabled, ok := raw["enabled"]; ok {
		value, ok := enabled.(bool)
		if !ok {
			return config, &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor enabled must be boolean", Context: "enabled"}
		}
		config.Enabled = value
	}
	if modelsRaw, ok := raw["worker_models"]; ok {
		models, err := stringList(modelsRaw, "worker_models")
		if err != nil {
			return config, err
		}
		config.WorkerModels = models
	} else if model := strings.TrimSpace(stringValue(raw["worker_model"])); model != "" {
		config.WorkerModels = []string{model}
	}
	if modelsRaw, ok := raw["advisor_models"]; ok {
		models, err := stringList(modelsRaw, "advisor_models")
		if err != nil {
			return config, err
		}
		config.AdvisorModels = models
	} else if model := strings.TrimSpace(stringValue(raw["advisor_model"])); model != "" {
		config.AdvisorModels = []string{model}
	}
	if n, ok, err := intField(raw, "depth"); err != nil {
		return config, err
	} else if ok {
		config.Depth = n
		config.DepthSet = true
	}
	for _, name := range []string{"max_get_advice_calls", "max_advice_calls"} {
		if n, ok, err := intField(raw, name); err != nil {
			return config, err
		} else if ok {
			config.MaxAdviceCalls = n
			break
		}
	}
	if n, ok, err := intField(raw, "advisor_max_tokens"); err != nil {
		return config, err
	} else if ok {
		config.AdvisorMaxTokens = n
	}
	if n, ok, err := intField(raw, "advisor_timeout_ms"); err != nil {
		return config, err
	} else if ok {
		config.AdvisorTimeoutMS = n
	}
	return config, nil
}

func mergeSocratesConfig(base, override socratesConfig) socratesConfig {
	if !override.Enabled {
		base.Enabled = false
	}
	if override.DepthSet {
		base.Depth = override.Depth
		base.DepthSet = true
	}
	if len(override.WorkerModels) > 0 {
		base.WorkerModels = append([]string(nil), override.WorkerModels...)
	}
	if len(override.AdvisorModels) > 0 {
		base.AdvisorModels = append([]string(nil), override.AdvisorModels...)
	}
	if override.MaxAdviceCalls != 0 {
		base.MaxAdviceCalls = override.MaxAdviceCalls
	}
	if override.AdvisorMaxTokens != 0 {
		base.AdvisorMaxTokens = override.AdvisorMaxTokens
	}
	if override.AdvisorTimeoutMS != 0 {
		base.AdvisorTimeoutMS = override.AdvisorTimeoutMS
	}
	return base
}

func normalizeSocratesConfig(config *socratesConfig, req *types.OpenAIChatRequest) error {
	if !config.DepthSet {
		config.Depth = defaultOrchestrationDepth
	}
	if config.Depth < 0 || config.Depth > maxOrchestrationDepth {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter orchestration depth must be between 0 and 4", Context: "depth"}
	}
	if req.Depth == nil {
		value := config.Depth
		req.Depth = &value
	}
	if len(config.WorkerModels) == 0 {
		config.WorkerModels = append([]string(nil), defaultSocratesWorkerModels...)
	}
	if len(config.WorkerModels) == 0 || len(config.WorkerModels) > 8 {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor worker_models must contain 1-8 models", Context: "worker_models"}
	}
	if len(config.AdvisorModels) == 0 {
		config.AdvisorModels = append([]string(nil), defaultSocratesAdvisorModels...)
	}
	if len(config.AdvisorModels) == 0 || len(config.AdvisorModels) > 8 {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor advisor_models must contain 1-8 models", Context: "advisor_models"}
	}
	if config.MaxAdviceCalls == 0 {
		config.MaxAdviceCalls = defaultSocratesAdviceCalls
	}
	if config.MaxAdviceCalls < 0 || config.MaxAdviceCalls > maxSocratesAdviceCalls {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor max_get_advice_calls must be between 0 and 3", Context: "max_get_advice_calls"}
	}
	if config.AdvisorMaxTokens == 0 {
		config.AdvisorMaxTokens = defaultSocratesAdvisorMaxTokens
	}
	if config.AdvisorMaxTokens < 1 || config.AdvisorMaxTokens > maxSocratesAdvisorMaxTokens {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor advisor_max_tokens must be between 1 and 8192", Context: "advisor_max_tokens"}
	}
	if config.AdvisorTimeoutMS == 0 {
		config.AdvisorTimeoutMS = defaultSocratesAdvisorTimeoutMS
	}
	if config.AdvisorTimeoutMS < 1000 || config.AdvisorTimeoutMS > maxSocratesAdvisorTimeoutMS {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor advisor_timeout_ms must be between 1000 and 180000", Context: "advisor_timeout_ms"}
	}
	for i, model := range config.WorkerModels {
		resolved := resolveFusionModelID(model)
		if resolved == "" || isOrchestrationModel(resolved) {
			return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor worker_models must be concrete model ids", Context: "worker_models"}
		}
		config.WorkerModels[i] = resolved
	}
	for i, model := range config.AdvisorModels {
		resolved := resolveFusionModelID(model)
		if resolved == "" {
			return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor advisor_models must contain non-empty model ids", Context: "advisor_models"}
		}
		config.AdvisorModels[i] = resolved
	}
	return nil
}

func socratesBuiltInPrompts() (string, string) {
	socratesPromptMu.RLock()
	defer socratesPromptMu.RUnlock()
	return socratesPromptCache.Worker, socratesPromptCache.Advisor
}

func socratesPromptsRequired() bool {
	return os.Getenv("TR_REQUIRE_SOCRATES_PROMPTS") == "1" ||
		(os.Getenv("QUILL_GCP_PROJECT_ID") != "" && os.Getenv("TR_ALLOW_DEFAULT_SOCRATES_PROMPTS") != "1")
}

func serveSocratesNonStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config socratesConfig,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestLogID string,
) {
	requestStarted := time.Now()
	requestID := newRequestID()
	final, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, err := runSocrates(ctx, br, req, config, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, nil, 0, nil)
	if err != nil {
		writeFusionError(ctx, conn, trGateway, err)
		return
	}
	totalIn, totalOut := socratesUsageTotals(workerAttempts, advisorAttempts)
	responseModel := final.Model
	if responseModel == "" {
		responseModel = config.WorkerModels[0]
	}
	var body bytes.Buffer
	if err := writeSocratesChatCompletionResponse(
		&body,
		requestID,
		responseModel,
		final.Result.Text,
		final.Result.ToolCalls,
		totalIn,
		totalOut,
		final.Result.Usage,
		time.Now().Unix(),
		final.Result.FinishReason,
		socratesResponseDetails(config, workerAttempts, advisorAttempts, responseModel, adviceCalls, budgetExhausted),
	); err != nil {
		writeError(conn, 500, "socrates response encoding error")
		return
	}
	fmt.Fprintf(os.Stderr,
		"socrates.request_end request_log_id=%q request_id=%q mode=nonstream outcome=%q advice_call_count=%d advice_budget_exhausted=%t selected_model=%q elapsed_ms=%d\n",
		requestLogID, requestID, "success", adviceCalls, budgetExhausted, responseModel, time.Since(requestStarted).Milliseconds(),
	)
	writeJSONResponse(conn, 200, body.Bytes())
}

func serveSocratesStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config socratesConfig,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestLogID string,
) {
	requestStarted := time.Now()
	requestID := newRequestID()
	created := time.Now().Unix()
	if err := writeResponseHead(conn, 200, "text/event-stream"); err != nil {
		return
	}
	chunkW := newChunkedWriter(conn)
	defer chunkW.Close()
	statsW := newStreamStatsWriter(chunkW)
	_ = writeSocratesStreamEvent(statsW, requestID, req.Model, created, map[string]any{
		"event":                "socrates.started",
		"depth_initial":        config.Depth,
		"max_get_advice_calls": config.MaxAdviceCalls,
	})
	observer := func(stage string, index int, model string) adapter.StreamObserver {
		return func(delta adapter.StreamDelta) {
			event := map[string]any{
				"event":      stage + "." + delta.Type,
				"stage":      stage,
				"index":      index,
				"model":      model,
				"delta_type": delta.Type,
			}
			if delta.Text != "" {
				if delta.Type == "thinking_delta" {
					event["thinking"] = delta.Text
				} else {
					event["text"] = delta.Text
				}
			}
			if delta.Signature != "" {
				event["signature"] = delta.Signature
			}
			_ = writeSocratesStreamEvent(statsW, requestID, req.Model, created, event)
		}
	}
	final, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, err := runSocrates(ctx, br, req, config, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, statsW, created, observer)
	if err != nil {
		_ = writeSocratesStreamError(statsW, requestID, req.Model, created, err)
		return
	}
	responseModel := final.Model
	if responseModel == "" {
		responseModel = config.WorkerModels[0]
	}
	if len(final.Result.ToolCalls) > 0 {
		_ = writeSocratesStreamEvent(statsW, requestID, responseModel, created, map[string]any{
			"event":      "socrates.tool_calls",
			"tool_calls": final.Result.ToolCalls,
		})
	} else if text := strings.TrimSpace(final.Result.Text); text != "" {
		_ = writeFusionStreamDelta(statsW, requestID, responseModel, created, map[string]any{"content": text}, "")
	}
	if err := writeFusionStreamDelta(statsW, requestID, responseModel, created, map[string]any{}, final.Result.FinishReason); err != nil {
		return
	}
	if chatIncludeUsage(req) {
		totalIn, totalOut := socratesUsageTotals(workerAttempts, advisorAttempts)
		usage := final
		usage.InputTokens = totalIn
		usage.OutputTokens = totalOut
		_ = writeFusionStreamUsage(statsW, requestID, responseModel, created, usage, socratesTotalCostMicrodollars(workerAttempts, advisorAttempts))
	}
	_, _ = statsW.Write([]byte("data: [DONE]\n\n"))
	fmt.Fprintf(os.Stderr,
		"socrates.request_end request_log_id=%q request_id=%q mode=stream outcome=%q advice_call_count=%d advice_budget_exhausted=%t selected_model=%q elapsed_ms=%d\n",
		requestLogID, requestID, "success", adviceCalls, budgetExhausted, responseModel, time.Since(requestStarted).Milliseconds(),
	)
}

func runSocrates(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config socratesConfig,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
	streamW io.Writer,
	streamCreated int64,
	observerFactory func(stage string, index int, model string) adapter.StreamObserver,
) (fusionCallResult, []fusionCallResult, []fusionCallResult, int, bool, error) {
	var lastErr error
	for i, workerModel := range config.WorkerModels {
		final, workers, advisors, adviceCalls, budgetExhausted, err := runSocratesWorkerLoop(ctx, br, req, config, workerModel, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, streamW, streamCreated, observerFactory)
		if err == nil {
			return final, workers, advisors, adviceCalls, budgetExhausted, nil
		}
		lastErr = err
		fmt.Fprintf(os.Stderr,
			"socrates.worker_attempt request_log_id=%q request_id=%q model=%q attempt=%d outcome=%q error=%q\n",
			requestLogID, requestID, workerModel, i+1, "error", err.Error(),
		)
		if streamW != nil {
			_ = writeSocratesStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event": "worker.failed",
				"stage": "worker",
				"index": i,
				"model": workerModel,
				"error": err.Error(),
			})
		}
	}
	if lastErr != nil {
		return fusionCallResult{}, nil, nil, 0, false, lastErr
	}
	return fusionCallResult{}, nil, nil, 0, false, &adapter.AdapterError{Status: 502, Message: "trustedrouter/socrates worker models produced no response", Context: "socrates.worker"}
}

func runSocratesWorkerLoop(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config socratesConfig,
	workerModel string,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
	streamW io.Writer,
	streamCreated int64,
	observerFactory func(stage string, index int, model string) adapter.StreamObserver,
) (fusionCallResult, []fusionCallResult, []fusionCallResult, int, bool, error) {
	messages := append([]types.OpenAIChatMessage{}, req.Messages...)
	workerAttempts := make([]fusionCallResult, 0, config.MaxAdviceCalls+2)
	advisorAttempts := make([]fusionCallResult, 0, config.MaxAdviceCalls)
	adviceCalls := 0
	budgetExhausted := false
	allowAdviceTool := config.MaxAdviceCalls > 0
	for turn := 0; turn < config.MaxAdviceCalls+3; turn++ {
		if streamW != nil {
			_ = writeSocratesStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event": "worker.started",
				"stage": "worker",
				"index": turn,
				"model": workerModel,
			})
		}
		workerReq := socratesWorkerRequest(req, workerModel, messages, config, allowAdviceTool)
		var observer adapter.StreamObserver
		if observerFactory != nil {
			observer = observerFactory("worker", turn, workerModel)
		}
		worker, err := runFusionCallObserved(ctx, br, workerReq, trGateway, secretCache, bearer, "socrates.worker", fmt.Sprintf("%s:worker:%d", requestID, turn), requestLogID, originalInput, false, observer, streamW != nil)
		if err != nil {
			return fusionCallResult{}, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, err
		}
		workerAttempts = append(workerAttempts, worker)
		if streamW != nil {
			_ = writeSocratesStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event":  "worker.done",
				"stage":  "worker",
				"index":  turn,
				"model":  workerModel,
				"detail": socratesSafeCallDetails(worker, true),
			})
		}
		adviceCall, hasAdvice := socratesAdviceToolCall(worker.Result.ToolCalls)
		if !hasAdvice {
			if strings.TrimSpace(worker.Result.Text) == "" && len(worker.Result.ToolCalls) == 0 {
				return fusionCallResult{}, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, &adapter.AdapterError{Status: 502, Message: "trustedrouter/socrates worker returned an empty response", Context: "socrates.worker"}
			}
			return worker, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, nil
		}
		if adviceCalls >= config.MaxAdviceCalls {
			budgetExhausted = true
			fmt.Fprintf(os.Stderr,
				"socrates.advice_budget_exhausted request_log_id=%q request_id=%q worker_model=%q depth_remaining=%d\n",
				requestLogID, requestID, workerModel, config.Depth,
			)
			messages = append(messages, socratesAssistantToolMessage(adviceCall), types.OpenAIChatMessage{
				Role:       "tool",
				Name:       socratesAdviceToolName,
				ToolCallID: socratesToolCallID(adviceCall, turn),
				Content:    "Advice budget exhausted. Answer now.",
			})
			allowAdviceTool = false
			continue
		}
		adviceCalls++
		fmt.Fprintf(os.Stderr,
			"socrates.advice_call request_log_id=%q request_id=%q worker_model=%q call_index=%d depth_remaining=%d advisor_models=%q\n",
			requestLogID, requestID, workerModel, adviceCalls, config.Depth, strings.Join(config.AdvisorModels, ","),
		)
		if streamW != nil {
			_ = writeSocratesStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event": "advice.started",
				"stage": "advisor",
				"index": adviceCalls - 1,
			})
		}
		adviceText, attempts := runSocratesAdvice(ctx, br, req, config, messages, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, streamW, streamCreated, observerFactory)
		advisorAttempts = append(advisorAttempts, attempts...)
		if strings.TrimSpace(adviceText) == "" {
			adviceText = "Advisor unavailable. Continue with your best answer now."
		}
		messages = append(messages, socratesAssistantToolMessage(adviceCall), types.OpenAIChatMessage{
			Role:       "tool",
			Name:       socratesAdviceToolName,
			ToolCallID: socratesToolCallID(adviceCall, turn),
			Content:    adviceText,
		})
	}
	return fusionCallResult{}, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, &adapter.AdapterError{Status: 502, Message: "trustedrouter/socrates did not complete after advice", Context: "socrates"}
}

func runSocratesAdvice(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config socratesConfig,
	messages []types.OpenAIChatMessage,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
	streamW io.Writer,
	streamCreated int64,
	observerFactory func(stage string, index int, model string) adapter.StreamObserver,
) (string, []fusionCallResult) {
	attempts := make([]fusionCallResult, 0, len(config.AdvisorModels))
	var lastErr error
	for i, advisorModel := range config.AdvisorModels {
		if streamW != nil {
			_ = writeSocratesStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event": "advisor.started",
				"stage": "advisor",
				"index": i,
				"model": advisorModel,
			})
		}
		var result fusionCallResult
		var err error
		if isFusionModel(advisorModel) {
			result, err = runSocratesFusionAdvisor(ctx, br, req, config, advisorModel, messages, trGateway, secretCache, bearer, fmt.Sprintf("%s:advisor:%d", requestID, i), requestLogID, originalInput)
		} else {
			advisorReq := socratesAdvisorRequest(req, advisorModel, messages, config)
			var observer adapter.StreamObserver
			if observerFactory != nil {
				observer = observerFactory("advisor", i, advisorModel)
			}
			timeout := time.Duration(config.AdvisorTimeoutMS) * time.Millisecond
			attemptCtx, cancel := context.WithTimeout(ctx, timeout)
			result, err = runFusionCallObserved(attemptCtx, br, advisorReq, trGateway, secretCache, bearer, "socrates.advisor", fmt.Sprintf("%s:advisor:%d", requestID, i), requestLogID, originalInput, false, observer, streamW != nil)
			cancel()
		}
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr,
				"socrates.advisor_failed request_log_id=%q request_id=%q model=%q attempt=%d error=%q\n",
				requestLogID, requestID, advisorModel, i+1, err.Error(),
			)
			continue
		}
		attempts = append(attempts, result)
		if streamW != nil {
			_ = writeSocratesStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event":  "advisor.done",
				"stage":  "advisor",
				"index":  i,
				"model":  advisorModel,
				"detail": socratesSafeCallDetails(result, false),
			})
		}
		text := strings.TrimSpace(result.Result.Text)
		if text == "" || fusionLooksLikeRefusal(text) {
			continue
		}
		return text, attempts
	}
	if lastErr != nil {
		fmt.Fprintf(os.Stderr,
			"socrates.advisor_unavailable request_log_id=%q request_id=%q error=%q\n",
			requestLogID, requestID, lastErr.Error(),
		)
	}
	return "", attempts
}

func runSocratesFusionAdvisor(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config socratesConfig,
	advisorModel string,
	messages []types.OpenAIChatMessage,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
) (fusionCallResult, error) {
	if config.Depth <= 0 {
		fmt.Fprintf(os.Stderr,
			"socrates.depth_blocked request_log_id=%q request_id=%q model=%q depth_remaining=%d\n",
			requestLogID, requestID, advisorModel, config.Depth,
		)
		return fusionCallResult{}, &adapter.AdapterError{Status: 400, Message: "trustedrouter orchestration depth exhausted", Context: "depth"}
	}
	childDepth := config.Depth - 1
	advisorReq := socratesAdvisorRequest(req, advisorModel, messages, config)
	advisorReq.Depth = &childDepth
	fusionConfig, requested, err := fusionConfigForRequest(advisorReq)
	if err != nil {
		return fusionCallResult{}, err
	}
	if !requested {
		return fusionCallResult{}, &adapter.AdapterError{Status: 400, Message: "advisor model is not a supported orchestration model", Context: "advisor_model"}
	}
	if len(fusionConfig.AnalysisModels) == 0 {
		if preset, panel, ok := fusionPresetPanelForModel(advisorReq.Model); ok {
			fusionConfig.Preset = preset
			fusionConfig.AnalysisModels = panel
		} else {
			fusionConfig.AnalysisModels = append([]string(nil), fusionQualityPanel...)
		}
	}
	if fusionConfig.SelectionStrategy == "" {
		fusionConfig.SelectionStrategy = defaultFusionSelectionStrategy
	}
	for i, model := range fusionConfig.AnalysisModels {
		fusionConfig.AnalysisModels[i] = resolveFusionModelID(model)
	}
	finalModels, err := fusionFinalModels(fusionConfig, advisorReq.Model, fusionConfig.AnalysisModels[0])
	if err != nil {
		return fusionCallResult{}, err
	}
	judgeModels, err := fusionJudgeModels(fusionConfig, finalModels[0])
	if err != nil {
		return fusionCallResult{}, err
	}
	codeModel := isFusionCodeModel(advisorReq.Model)
	fusionConfig.CodeModel = codeModel
	if codeModel {
		fusionConfig.AnalysisModels = applyFusionCodeSwap(fusionConfig.AnalysisModels)
		judgeModels = applyFusionCodeSwap(judgeModels)
	}
	fusionConfig.BuiltInPanelPrompt, fusionConfig.BuiltInFinalPrompt = fusionBuiltInPrompts(codeModel)
	panel, err := runFusionPanel(ctx, br, advisorReq, fusionConfig, trGateway, secretCache, bearer, requestID+":fusion", requestLogID)
	if err != nil {
		return fusionCallResult{}, err
	}
	synthesisPanel, err := fusionPanelForSynthesis(panel, fusionConfig.SelectionStrategy)
	if err != nil {
		return fusionCallResult{}, err
	}
	judge, _, err := runFusionJudge(ctx, br, advisorReq, fusionConfig, judgeModels, synthesisPanel, trGateway, secretCache, bearer, requestID+":fusion", requestLogID)
	if err != nil {
		return fusionCallResult{}, err
	}
	final, _, err := runFusionFinal(ctx, br, advisorReq, fusionConfig, finalModels, judge.Result.Text, synthesisPanel, trGateway, secretCache, bearer, requestID+":fusion", requestLogID, originalInput)
	if err != nil {
		return fusionCallResult{}, err
	}
	return final, nil
}

func socratesWorkerRequest(req *types.OpenAIChatRequest, model string, messages []types.OpenAIChatMessage, config socratesConfig, allowAdviceTool bool) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = model
	out.Models = nil
	forceFusionThroughputRouting(out)
	out.Stream = false
	out.Plugins = nil
	out.Messages = prependSystem(messages, config.BuiltInWorkerPrompt)
	out.Tools = stripTrustedRouterToolEntries(out.Tools)
	if allowAdviceTool {
		out.Tools = append(out.Tools, socratesAdviceTool())
	}
	if len(out.Tools) == 0 {
		out.ToolChoice = nil
	}
	out.Metadata = socratesMetadata(out.Metadata, "worker", model, config)
	return out
}

func socratesAdvisorRequest(req *types.OpenAIChatRequest, model string, messages []types.OpenAIChatMessage, config socratesConfig) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = model
	out.Models = nil
	forceFusionThroughputRouting(out)
	out.Stream = false
	out.Plugins = nil
	out.Tools = nil
	out.ToolChoice = nil
	out.ResponseFormat = nil
	out.MaxTokens = &config.AdvisorMaxTokens
	out.Messages = prependSystem(messages, config.BuiltInAdvisorPrompt)
	out.Metadata = socratesMetadata(out.Metadata, "advisor", model, config)
	return out
}

func socratesAdviceTool() map[string]any {
	return map[string]any{
		"type": "function",
		"function": map[string]any{
			"name":        socratesAdviceToolName,
			"description": "Ask a stronger TrustedRouter advisor for private guidance only when stuck, uncertain, or facing a high-stakes decision. Do not use for routine or straightforward work.",
			"parameters": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties":           map[string]any{},
			},
		},
	}
}

func rejectSocratesToolCollision(tools []any, toolChoice any) error {
	for _, tool := range tools {
		m, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		if functionNameFromTool(m) == socratesAdviceToolName {
			return &adapter.AdapterError{Status: 400, Message: "_trustedrouter_get_advice is reserved for TrustedRouter Socrates", Context: "tools"}
		}
	}
	if toolChoiceFunctionName(toolChoice) == socratesAdviceToolName {
		return &adapter.AdapterError{Status: 400, Message: "_trustedrouter_get_advice is reserved for TrustedRouter Socrates", Context: "tool_choice"}
	}
	return nil
}

func functionNameFromTool(tool map[string]any) string {
	fn, ok := tool["function"].(map[string]any)
	if !ok {
		return ""
	}
	return strings.TrimSpace(stringValue(fn["name"]))
}

func toolChoiceFunctionName(toolChoice any) string {
	m, ok := toolChoice.(map[string]any)
	if !ok {
		return ""
	}
	fn, ok := m["function"].(map[string]any)
	if !ok {
		return ""
	}
	return strings.TrimSpace(stringValue(fn["name"]))
}

func stripTrustedRouterToolEntries(tools []any) []any {
	if len(tools) == 0 {
		return nil
	}
	out := make([]any, 0, len(tools))
	for _, item := range tools {
		m, ok := item.(map[string]any)
		if !ok {
			out = append(out, item)
			continue
		}
		toolType := strings.ToLower(strings.TrimSpace(stringValue(m["type"])))
		if strings.HasPrefix(toolType, "trustedrouter:") {
			continue
		}
		out = append(out, item)
	}
	return out
}

func socratesAdviceToolCall(calls []types.ToolCall) (types.ToolCall, bool) {
	for _, call := range calls {
		if strings.TrimSpace(call.Name) == socratesAdviceToolName {
			return call, true
		}
	}
	return types.ToolCall{}, false
}

func socratesAssistantToolMessage(call types.ToolCall) types.OpenAIChatMessage {
	return types.OpenAIChatMessage{
		Role:    "assistant",
		Content: nil,
		ToolCalls: []types.OpenAIToolCall{{
			ID:   socratesToolCallID(call, 0),
			Type: "function",
			Function: types.OpenAIToolFunction{
				Name:      socratesAdviceToolName,
				Arguments: "{}",
			},
		}},
	}
}

func socratesToolCallID(call types.ToolCall, index int) string {
	if call.ID != "" {
		return call.ID
	}
	if call.CallID != "" {
		return call.CallID
	}
	return fmt.Sprintf("call_socrates_advice_%d", index+1)
}

func socratesMetadata(input map[string]any, stage string, model string, config socratesConfig) map[string]any {
	out := map[string]any{}
	for k, v := range input {
		out[k] = v
	}
	out["trustedrouter_router"] = "trustedrouter/socrates-1.0"
	out["trustedrouter_socrates_stage"] = stage
	out["trustedrouter_socrates_model"] = model
	out["trustedrouter_orchestration_depth"] = config.Depth
	return out
}

func socratesResponseDetails(config socratesConfig, workerAttempts []fusionCallResult, advisorAttempts []fusionCallResult, selectedModel string, adviceCalls int, budgetExhausted bool) map[string]any {
	details := map[string]any{
		"version":                 "1.0",
		"selected_model":          selectedModel,
		"depth_initial":           config.Depth,
		"max_get_advice_calls":    config.MaxAdviceCalls,
		"advice_call_count":       adviceCalls,
		"advice_budget_exhausted": budgetExhausted,
		"worker_attempts":         socratesSafeCallDetailsList(workerAttempts, true),
		"advisor_attempts":        socratesSafeCallDetailsList(advisorAttempts, false),
	}
	if cost := socratesTotalCostMicrodollars(workerAttempts, advisorAttempts); cost > 0 {
		details["cost_microdollars"] = cost
	}
	return details
}

func socratesSafeCallDetailsList(items []fusionCallResult, includeText bool) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, socratesSafeCallDetails(item, includeText))
	}
	return out
}

func socratesSafeCallDetails(item fusionCallResult, includeText bool) map[string]any {
	detail := fusionCallDetails(item)
	if !includeText {
		delete(detail, "visible_answer")
		delete(detail, "raw_output")
		delete(detail, "thinking")
		delete(detail, "tool_calls")
	}
	return detail
}

func socratesUsageTotals(groups ...[]fusionCallResult) (int, int) {
	var inputs int
	var outputs int
	for _, items := range groups {
		for _, item := range items {
			inputs += item.InputTokens
			outputs += item.OutputTokens
		}
	}
	if inputs < 1 {
		inputs = 1
	}
	if outputs < 1 {
		outputs = 1
	}
	return inputs, outputs
}

func socratesTotalCostMicrodollars(groups ...[]fusionCallResult) int {
	total := 0
	for _, items := range groups {
		for _, item := range items {
			if item.SettlementResult != nil {
				total += item.SettlementResult.CostMicrodollars
			}
		}
	}
	return total
}

func writeSocratesChatCompletionResponse(
	w io.Writer,
	requestID string,
	model string,
	text string,
	toolCalls []types.ToolCall,
	inputTokens int,
	outputTokens int,
	usage *adapter.StreamUsage,
	created int64,
	finishReason string,
	details map[string]any,
) error {
	var body bytes.Buffer
	if err := adapter.WriteChatCompletionResponse(
		&body,
		requestID,
		model,
		text,
		toolCalls,
		inputTokens,
		outputTokens,
		usage,
		created,
		finishReason,
	); err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(body.Bytes(), &payload); err != nil {
		return err
	}
	payload["trustedrouter"] = map[string]any{"socrates": details}
	if cost, ok := fusionCostMicrodollars(details); ok {
		if usage, ok := payload["usage"].(map[string]any); ok {
			usage["cost_microdollars"] = cost
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = w.Write(encoded)
	return err
}

func writeSocratesStreamEvent(w io.Writer, requestID string, model string, created int64, event map[string]any) error {
	chunk := map[string]any{
		"id":            requestID,
		"object":        "chat.completion.chunk",
		"created":       created,
		"model":         model,
		"choices":       []map[string]any{},
		"trustedrouter": map[string]any{"socrates": event},
	}
	body, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte("data: ")); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n\n"))
	return err
}

func writeSocratesStreamError(w io.Writer, requestID string, model string, created int64, err error) error {
	if err == nil {
		return nil
	}
	if writeErr := writeSocratesStreamEvent(w, requestID, model, created, map[string]any{
		"event": "socrates.error",
		"error": err.Error(),
	}); writeErr != nil {
		return writeErr
	}
	_, writeErr := w.Write([]byte("data: [DONE]\n\n"))
	return writeErr
}
