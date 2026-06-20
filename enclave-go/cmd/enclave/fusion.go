package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const trustedRouterFusionModel = "trustedrouter/fusion"
const trustedRouterFusionTool = "trustedrouter:fusion"
const defaultFusionSelectionStrategy = "synthesize_non_refusals"

var fusionQualityPanel = []string{
	"minimax/minimax-m3",
	"moonshotai/kimi-k2.7-code",
	"z-ai/glm-5.2",
	"google/gemma-4-31b-it",
	"deepseek/deepseek-v4-pro",
}

var fusionBudgetPanel = []string{
	"google/gemini-3-flash-preview",
	"moonshotai/kimi-k2.7-code",
	"deepseek/deepseek-v4-pro",
}

var fusionModelAliases = map[string]string{
	"~anthropic/claude-opus-latest": "anthropic/claude-opus-4.8",
	"~anthropic/claude-latest":      "anthropic/claude-opus-4.8",
	"~openai/gpt-latest":            "openai/gpt-5.5",
	"~google/gemini-pro-latest":     "google/gemini-3.1-pro-preview",
	"~google/gemini-flash-latest":   "google/gemini-3-flash-preview",
	"~moonshotai/kimi-latest":       "moonshotai/kimi-k2.7-code",
	"~kimi/latest":                  "moonshotai/kimi-k2.7-code",
	"~zai/glm-latest":               "z-ai/glm-5.2",
}

type fusionConfig struct {
	Enabled             bool
	AnalysisModels      []string
	JudgeModel          string
	JudgeModels         []string
	FinalModels         []string
	MaxToolCalls        int
	MaxCompletionTokens int
	SelectionStrategy   string
	Preset              string
}

type fusionCallResult struct {
	Result           adapter.StreamResult
	Model            string
	Endpoint         string
	InputTokens      int
	OutputTokens     int
	UsageEstimated   bool
	Authorization    *trustedrouter.Authorization
	SettlementResult *trustedrouter.SettleResult
}

func maybeServeFusion(
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
	config, requested, err := fusionConfigForRequest(req)
	if err != nil {
		return true, err
	}
	if !requested {
		return false, nil
	}
	if !config.Enabled {
		if req.Model == trustedRouterFusionModel {
			return true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion cannot be disabled without selecting a concrete model", Context: "plugins.fusion.enabled"}
		}
		return false, nil
	}
	if trGateway == nil || !trGateway.Enabled() {
		return true, &adapter.AdapterError{Status: 503, Message: "trustedrouter/fusion requires the TrustedRouter control plane", Context: "trustedrouter/fusion"}
	}
	if len(config.AnalysisModels) == 0 {
		config.AnalysisModels = append([]string(nil), fusionQualityPanel...)
	}
	if len(config.AnalysisModels) > 8 {
		return true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion analysis_models must contain 1-8 models", Context: "analysis_models"}
	}
	if config.SelectionStrategy == "" {
		config.SelectionStrategy = defaultFusionSelectionStrategy
	}
	switch config.SelectionStrategy {
	case "synthesize", "synthesize_non_refusals", "first_success", "first_non_refusal":
	default:
		return true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion selection_strategy must be synthesize, synthesize_non_refusals, first_success, or first_non_refusal", Context: "selection_strategy"}
	}
	if config.MaxToolCalls < 0 || config.MaxToolCalls > 16 {
		return true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion max_tool_calls must be between 1 and 16", Context: "max_tool_calls"}
	}
	for i, model := range config.AnalysisModels {
		config.AnalysisModels[i] = resolveFusionModelID(model)
	}
	finalModels, err := fusionFinalModels(config, req.Model, config.AnalysisModels[0])
	if err != nil {
		return true, err
	}
	judgeModels, err := fusionJudgeModels(config, finalModels[0])
	if err != nil {
		return true, err
	}

	if req.Stream {
		serveFusionStreaming(ctx, conn, br, req, config, finalModels, judgeModels, trGateway, secretCache, bearer, originalInput, requestLogID)
	} else {
		serveFusionNonStreaming(ctx, conn, br, req, config, finalModels, judgeModels, trGateway, secretCache, bearer, originalInput, requestLogID)
	}
	return true, nil
}

func fusionConfigForRequest(req *types.OpenAIChatRequest) (fusionConfig, bool, error) {
	config := fusionConfig{Enabled: true}
	requested := req.Model == trustedRouterFusionModel

	if pluginConfig, ok, err := fusionConfigFromPlugins(req.Plugins); err != nil {
		return fusionConfig{}, true, err
	} else if ok {
		config = mergeFusionConfig(config, pluginConfig)
		requested = true
	}

	cleanTools, toolConfig, toolRequested, err := fusionConfigFromTools(req.Tools)
	if err != nil {
		return fusionConfig{}, true, err
	}
	if toolRequested {
		config = mergeFusionConfig(config, toolConfig)
		requested = true
		req.Tools = cleanTools
	}

	return config, requested, nil
}

func fusionConfigFromPlugins(plugins []any) (fusionConfig, bool, error) {
	for _, item := range plugins {
		m, ok := item.(map[string]any)
		if !ok {
			return fusionConfig{}, false, &adapter.AdapterError{Status: 400, Message: "plugin must be an object", Context: "plugins"}
		}
		if strings.TrimSpace(stringValue(m["id"])) != "fusion" {
			continue
		}
		config, err := parseFusionParameters(m)
		return config, true, err
	}
	return fusionConfig{}, false, nil
}

func fusionConfigFromTools(tools []any) ([]any, fusionConfig, bool, error) {
	if len(tools) == 0 {
		return tools, fusionConfig{}, false, nil
	}
	clean := make([]any, 0, len(tools))
	config := fusionConfig{Enabled: true}
	var requested bool
	for _, item := range tools {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fusionConfig{}, false, &adapter.AdapterError{Status: 400, Message: "tool must be an object", Context: "tools"}
		}
		toolType := strings.TrimSpace(stringValue(m["type"]))
		if strings.HasPrefix(toolType, "openrouter:") {
			return nil, fusionConfig{}, true, &adapter.AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools.type"}
		}
		if strings.HasPrefix(toolType, "trustedrouter:") && toolType != trustedRouterFusionTool {
			return nil, fusionConfig{}, true, &adapter.AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools.type"}
		}
		if toolType != trustedRouterFusionTool {
			clean = append(clean, item)
			continue
		}
		params, err := fusionParametersMap(m["parameters"], "tools.parameters")
		if err != nil {
			return nil, fusionConfig{}, true, err
		}
		parsed, err := parseFusionParameters(params)
		if err != nil {
			return nil, fusionConfig{}, true, err
		}
		config = mergeFusionConfig(config, parsed)
		requested = true
	}
	return clean, config, requested, nil
}

func fusionParametersMap(value any, context string) (map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion parameters must be an object", Context: context}
	}
	return m, nil
}

func parseFusionParameters(raw map[string]any) (fusionConfig, error) {
	config := fusionConfig{Enabled: true}
	if raw == nil {
		return config, nil
	}
	if enabled, ok := raw["enabled"]; ok {
		value, ok := enabled.(bool)
		if !ok {
			return config, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion enabled must be boolean", Context: "enabled"}
		}
		config.Enabled = value
	}
	if preset := strings.TrimSpace(strings.ToLower(stringValue(raw["preset"]))); preset != "" {
		switch preset {
		case "quality":
			config.AnalysisModels = append([]string(nil), fusionQualityPanel...)
		case "budget":
			config.AnalysisModels = append([]string(nil), fusionBudgetPanel...)
		default:
			return config, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion preset must be quality or budget", Context: "preset"}
		}
		config.Preset = preset
	}
	if modelsRaw, ok := raw["analysis_models"]; ok {
		models, err := stringList(modelsRaw, "analysis_models")
		if err != nil {
			return config, err
		}
		config.AnalysisModels = models
	}
	if model := strings.TrimSpace(stringValue(raw["model"])); model != "" {
		config.JudgeModel = model
	}
	if modelsRaw, ok := raw["judge_models"]; ok {
		models, err := stringList(modelsRaw, "judge_models")
		if err != nil {
			return config, err
		}
		config.JudgeModels = models
	} else if modelsRaw, ok := raw["fallback_judges"]; ok {
		models, err := stringList(modelsRaw, "fallback_judges")
		if err != nil {
			return config, err
		}
		config.JudgeModels = models
	} else if modelsRaw, ok := raw["judges"]; ok {
		models, err := stringList(modelsRaw, "judges")
		if err != nil {
			return config, err
		}
		config.JudgeModels = models
	}
	if modelsRaw, ok := raw["final_models"]; ok {
		models, err := stringList(modelsRaw, "final_models")
		if err != nil {
			return config, err
		}
		config.FinalModels = models
	} else if modelsRaw, ok := raw["fallback_final_models"]; ok {
		models, err := stringList(modelsRaw, "fallback_final_models")
		if err != nil {
			return config, err
		}
		config.FinalModels = models
	} else if modelsRaw, ok := raw["synthesis_models"]; ok {
		models, err := stringList(modelsRaw, "synthesis_models")
		if err != nil {
			return config, err
		}
		config.FinalModels = models
	} else if modelsRaw, ok := raw["synthesizer_models"]; ok {
		models, err := stringList(modelsRaw, "synthesizer_models")
		if err != nil {
			return config, err
		}
		config.FinalModels = models
	}
	if n, ok, err := intField(raw, "max_tool_calls"); err != nil {
		return config, err
	} else if ok {
		config.MaxToolCalls = n
	}
	if n, ok, err := intField(raw, "max_completion_tokens"); err != nil {
		return config, err
	} else if ok {
		config.MaxCompletionTokens = n
	}
	if strategy := strings.TrimSpace(strings.ToLower(stringValue(raw["selection_strategy"]))); strategy != "" {
		config.SelectionStrategy = strategy
	} else if strategy := strings.TrimSpace(strings.ToLower(stringValue(raw["strategy"]))); strategy != "" {
		config.SelectionStrategy = strategy
	} else if strategy := strings.TrimSpace(strings.ToLower(stringValue(raw["type"]))); strategy != "" {
		config.SelectionStrategy = strategy
	}
	return config, nil
}

func mergeFusionConfig(base, override fusionConfig) fusionConfig {
	if !override.Enabled {
		base.Enabled = false
	}
	if len(override.AnalysisModels) > 0 {
		base.AnalysisModels = append([]string(nil), override.AnalysisModels...)
	}
	if override.JudgeModel != "" {
		base.JudgeModel = override.JudgeModel
	}
	if len(override.JudgeModels) > 0 {
		base.JudgeModels = append([]string(nil), override.JudgeModels...)
	}
	if len(override.FinalModels) > 0 {
		base.FinalModels = append([]string(nil), override.FinalModels...)
	}
	if override.MaxToolCalls != 0 {
		base.MaxToolCalls = override.MaxToolCalls
	}
	if override.MaxCompletionTokens != 0 {
		base.MaxCompletionTokens = override.MaxCompletionTokens
	}
	if override.SelectionStrategy != "" {
		base.SelectionStrategy = override.SelectionStrategy
	}
	if override.Preset != "" {
		base.Preset = override.Preset
	}
	return base
}

func serveFusionNonStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	finalModels []string,
	judgeModels []string,
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
	if config.SelectionStrategy != "synthesize" && config.SelectionStrategy != "synthesize_non_refusals" {
		selected, err := selectFusionPanelResult(panel, config.SelectionStrategy)
		if err != nil {
			writeFusionError(ctx, conn, trGateway, err)
			return
		}
		totalIn, totalOut := fusionPanelUsageTotals(panel)
		responseModel := selected.Model
		if responseModel == "" {
			responseModel = selectedRouteModel(selected, finalModels[0])
		}
		var body bytes.Buffer
		if err := adapter.WriteChatCompletionResponse(&body, requestID, responseModel, selected.Result.Text, selected.Result.ToolCalls, totalIn, totalOut, selected.Result.Usage, time.Now().Unix(), selected.Result.FinishReason); err != nil {
			writeError(conn, 500, "fusion response encoding error")
			return
		}
		fmt.Fprintf(os.Stderr,
			"enclave.fusion_complete request_log_id=%q request_id=%q mode=nonstream strategy=%q panel=%d selected_model=%q elapsed_ms=%d\n",
			requestLogID, requestID, config.SelectionStrategy, len(panel), responseModel, time.Since(requestStarted).Milliseconds(),
		)
		writeJSONResponse(conn, 200, body.Bytes())
		return
	}
	synthesisPanel, err := fusionPanelForSynthesis(panel, config.SelectionStrategy)
	if err != nil {
		writeFusionError(ctx, conn, trGateway, err)
		return
	}
	judge, judgeAttempts, err := runFusionJudge(ctx, br, req, config, judgeModels, synthesisPanel, trGateway, secretCache, bearer, requestID, requestLogID)
	if err != nil {
		writeFusionError(ctx, conn, trGateway, err)
		return
	}
	final, finalAttempts, err := runFusionFinal(ctx, br, req, finalModels, judge.Result.Text, synthesisPanel, trGateway, secretCache, bearer, requestID, requestLogID, originalInput)
	if err != nil {
		writeFusionError(ctx, conn, trGateway, err)
		return
	}
	totalIn, totalOut := fusionUsageTotals(panel, judgeAttempts, finalAttempts...)
	responseModel := final.Model
	if responseModel == "" {
		responseModel = finalModels[0]
	}
	var body bytes.Buffer
	if err := adapter.WriteChatCompletionResponse(&body, requestID, responseModel, final.Result.Text, final.Result.ToolCalls, totalIn, totalOut, final.Result.Usage, time.Now().Unix(), final.Result.FinishReason); err != nil {
		writeError(conn, 500, "fusion response encoding error")
		return
	}
	fmt.Fprintf(os.Stderr,
		"enclave.fusion_complete request_log_id=%q request_id=%q mode=nonstream panel=%d judge_model=%q judge_attempts=%d final_model=%q elapsed_ms=%d\n",
		requestLogID, requestID, len(panel), judge.Model, len(judgeAttempts), responseModel, time.Since(requestStarted).Milliseconds(),
	)
	writeJSONResponse(conn, 200, body.Bytes())
}

func serveFusionStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	finalModels []string,
	judgeModels []string,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestLogID string,
) {
	requestID := newRequestID()
	panel, judge, err := runFusionPanelAndJudge(ctx, br, req, config, judgeModels, trGateway, secretCache, bearer, requestID, requestLogID)
	if err != nil {
		writeFusionError(ctx, conn, trGateway, err)
		return
	}
	err = serveFusionFinalStreaming(ctx, conn, br, req, finalModels, judge.Result.Text, panel, trGateway, secretCache, bearer, requestID, requestLogID, originalInput)
	if err != nil {
		writeFusionError(ctx, conn, trGateway, err)
		return
	}
	_, _, _ = panel, judge, requestID
}

func runFusionPanelAndJudge(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	judgeModels []string,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
) ([]fusionCallResult, fusionCallResult, error) {
	panel, err := runFusionPanel(ctx, br, req, config, trGateway, secretCache, bearer, requestID, requestLogID)
	if err != nil {
		return nil, fusionCallResult{}, err
	}
	synthesisPanel, err := fusionPanelForSynthesis(panel, config.SelectionStrategy)
	if err != nil {
		return nil, fusionCallResult{}, err
	}
	judge, _, err := runFusionJudge(ctx, br, req, config, judgeModels, synthesisPanel, trGateway, secretCache, bearer, requestID, requestLogID)
	if err != nil {
		return nil, fusionCallResult{}, err
	}
	return synthesisPanel, judge, nil
}

func runFusionPanel(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
) ([]fusionCallResult, error) {
	panel := make([]fusionCallResult, 0, len(config.AnalysisModels))
	var successCount int
	var lastErr error
	for i, model := range config.AnalysisModels {
		panelReq := fusionPanelRequest(req, model, i, config.MaxCompletionTokens)
		result, err := runFusionCall(ctx, br, panelReq, trGateway, secretCache, bearer, "fusion.panel", fmt.Sprintf("%s:panel:%d", requestID, i), requestLogID, nil, false)
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr,
				"enclave.fusion_panel_failed request_log_id=%q request_id=%q model=%q error=%q\n",
				requestLogID, requestID, model, err.Error(),
			)
			panel = append(panel, fusionCallResult{
				Result: adapter.StreamResult{
					Text:         fmt.Sprintf("[panel member %d, model %s failed before producing an answer: %s]", i+1, model, err.Error()),
					FinishReason: "error",
				},
				Model: model,
			})
			continue
		}
		if strings.TrimSpace(result.Result.Text) == "" && len(result.Result.ToolCalls) == 0 {
			result.Result.Text = fmt.Sprintf("[panel member %d, model %s returned an empty answer; finish_reason=%s]", i+1, model, result.Result.FinishReason)
			result.Result.FinishReason = "empty"
			panel = append(panel, result)
			continue
		}
		successCount++
		panel = append(panel, result)
	}
	if successCount == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, &adapter.AdapterError{Status: 502, Message: "trustedrouter/fusion panel produced no successful responses", Context: "fusion.panel"}
	}
	return panel, nil
}

func runFusionJudge(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config fusionConfig,
	judgeModels []string,
	panel []fusionCallResult,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
) (fusionCallResult, []fusionCallResult, error) {
	attempts := make([]fusionCallResult, 0, len(judgeModels))
	var lastErr error
	for i, judgeModel := range judgeModels {
		judgeReq := fusionJudgeRequest(req, judgeModel, panel, config.MaxCompletionTokens)
		judge, err := runFusionCall(ctx, br, judgeReq, trGateway, secretCache, bearer, "fusion.judge", fmt.Sprintf("%s:judge:%d", requestID, i), requestLogID, nil, false)
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr,
				"enclave.fusion_judge_failed request_log_id=%q request_id=%q model=%q attempt=%d error=%q\n",
				requestLogID, requestID, judgeModel, i+1, err.Error(),
			)
			continue
		}
		attempts = append(attempts, judge)
		if !fusionJudgeResultUsable(judge) {
			fmt.Fprintf(os.Stderr,
				"enclave.fusion_judge_unusable request_log_id=%q request_id=%q model=%q attempt=%d finish_reason=%q\n",
				requestLogID, requestID, judgeModel, i+1, judge.Result.FinishReason,
			)
			continue
		}
		if fusionLooksLikeRefusal(judge.Result.Text) {
			fmt.Fprintf(os.Stderr,
				"enclave.fusion_judge_refused request_log_id=%q request_id=%q model=%q attempt=%d\n",
				requestLogID, requestID, judgeModel, i+1,
			)
			continue
		}
		return judge, attempts, nil
	}
	if lastErr != nil && len(attempts) == 0 {
		return fusionCallResult{}, attempts, lastErr
	}
	return fusionCallResult{}, attempts, &adapter.AdapterError{Status: 502, Message: "trustedrouter/fusion judges produced no usable non-refusal analysis", Context: "fusion.judge"}
}

func runFusionFinal(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	finalModels []string,
	judgeJSON string,
	panel []fusionCallResult,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
) (fusionCallResult, []fusionCallResult, error) {
	attempts := make([]fusionCallResult, 0, len(finalModels))
	var lastErr error
	for i, finalModel := range finalModels {
		finalReq := fusionFinalRequest(req, finalModel, judgeJSON, panel)
		idempotencyKey := requestID + ":final"
		if i > 0 {
			idempotencyKey = fmt.Sprintf("%s:final:%d", requestID, i)
		}
		final, err := runFusionCallValidated(
			ctx,
			br,
			finalReq,
			trGateway,
			secretCache,
			bearer,
			"fusion.final",
			idempotencyKey,
			requestLogID,
			originalInput,
			true,
			fusionValidateFinalResult,
			i == len(finalModels)-1,
		)
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr,
				"enclave.fusion_final_failed request_log_id=%q request_id=%q model=%q attempt=%d error=%q\n",
				requestLogID, requestID, finalModel, i+1, err.Error(),
			)
			continue
		}
		attempts = append(attempts, final)
		return final, attempts, nil
	}
	if lastErr != nil {
		return fusionCallResult{}, attempts, lastErr
	}
	return fusionCallResult{}, attempts, &adapter.AdapterError{Status: 502, Message: "trustedrouter/fusion final models produced no usable non-refusal answer", Context: "fusion.final"}
}

func runFusionCall(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	routeType string,
	idempotencyKey string,
	requestLogID string,
	originalInput any,
	broadcastContent bool,
) (fusionCallResult, error) {
	return runFusionCallValidated(ctx, br, req, trGateway, secretCache, bearer, routeType, idempotencyKey, requestLogID, originalInput, broadcastContent, nil, true)
}

func runFusionCallValidated(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	routeType string,
	idempotencyKey string,
	requestLogID string,
	originalInput any,
	broadcastContent bool,
	validateBeforeSettle func(adapter.StreamResult) error,
	useLongLastCandidateBudget bool,
) (fusionCallResult, error) {
	requestStarted := time.Now()
	authz, options, err := authorizeFusionCall(ctx, req, trGateway, secretCache, bearer, routeType, idempotencyKey)
	if err != nil {
		return fusionCallResult{}, err
	}
	if len(options) > 0 && options[0].Model != "" {
		req.Model = options[0].Model
	}
	anthropicReq, err := adapter.ToAnthropic(req, req.Model)
	if err != nil {
		if trGateway != nil && trGateway.Enabled() {
			_ = trGateway.Refund(ctx, authz, 400, "fusion_adapter_error", time.Since(requestStarted).Seconds(), req.Metadata)
		}
		return fusionCallResult{}, err
	}
	pr, pw := io.Pipe()
	selectedRoute := newSelectedRouteTracker()
	go invokeProviderStream(ctx, br, req, anthropicReq, pw, options, true, authz, selectedRoute, requestLogID, useLongLastCandidateBudget)
	result, err := adapter.CollectAnthropicText(pr)
	if err != nil {
		if trGateway != nil && trGateway.Enabled() {
			_ = trGateway.Refund(ctx, authz, 502, "provider_error", time.Since(requestStarted).Seconds(), req.Metadata)
		}
		return fusionCallResult{}, err
	}
	if strings.HasPrefix(routeType, "fusion.") {
		result.Text = fusionVisibleAnswer(result.Text)
		if routeType == "fusion.final" && strings.TrimSpace(result.Text) == "" && len(result.ToolCalls) == 0 {
			if trGateway != nil && trGateway.Enabled() {
				_ = trGateway.Refund(ctx, authz, 502, "empty_output", time.Since(requestStarted).Seconds(), req.Metadata)
			}
			return fusionCallResult{}, &adapter.AdapterError{Status: 502, Message: "trustedrouter/fusion final model returned an empty visible answer", Context: "fusion.final"}
		}
	}
	if validateBeforeSettle != nil {
		if err := validateBeforeSettle(result); err != nil {
			if trGateway != nil && trGateway.Enabled() {
				_ = trGateway.Refund(ctx, authz, statusFromControlPlaneError(err), "fusion_validation_error", time.Since(requestStarted).Seconds(), req.Metadata)
			}
			return fusionCallResult{}, err
		}
	}
	inputTokens, outputTokens, usageEstimated := realOrEstimatedTokens(
		result,
		trustedrouter.EstimateInputTokens(req),
		trustedrouter.EstimateOutputTokens(adapter.ResponsesOutputForUsage(result)),
	)
	selectedModel := selectedRoute.Model(req.Model, authz)
	selectedEndpoint := selectedRoute.Endpoint("", authz)
	usage := trustedrouter.Usage{
		RequestID:        idempotencyKey,
		InputTokens:      inputTokens,
		OutputTokens:     outputTokens,
		ElapsedSeconds:   maxDurationSeconds(time.Since(requestStarted), 0.001),
		UsageEstimated:   usageEstimated,
		FinishReason:     result.FinishReason,
		Streamed:         false,
		RouteType:        routeType,
		SelectedModel:    selectedModel,
		SelectedEndpoint: selectedEndpoint,
		User:             req.User,
		SessionID:        req.SessionID,
		Trace:            req.Trace,
		Metadata:         req.Metadata,
	}
	applyCacheUsage(&usage, result)
	var inputForBroadcast any
	var outputForBroadcast string
	if broadcastContent {
		inputForBroadcast = originalInput
		outputForBroadcast = result.Text
	}
	settleResult, err := settleAndBroadcast(ctx, trGateway, authz, secretCache, usage, req, inputForBroadcast, outputForBroadcast)
	if err != nil {
		return fusionCallResult{}, err
	}
	if selectedModel == "" && authz != nil {
		selectedModel = authz.Model
	}
	if selectedEndpoint == "" && authz != nil {
		selectedEndpoint = authz.EndpointID
	}
	return fusionCallResult{
		Result:           result,
		Model:            selectedModel,
		Endpoint:         selectedEndpoint,
		InputTokens:      inputTokens,
		OutputTokens:     outputTokens,
		UsageEstimated:   usageEstimated,
		Authorization:    authz,
		SettlementResult: settleResult,
	}, nil
}

func serveFusionFinalStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	finalModels []string,
	judgeJSON string,
	panel []fusionCallResult,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
) error {
	var lastErr error
	for i, finalModel := range finalModels {
		finalReq := fusionFinalRequest(req, finalModel, judgeJSON, panel)
		finalReq.Stream = true
		idempotencyKey := requestID + ":final"
		if i > 0 {
			idempotencyKey = fmt.Sprintf("%s:final:%d", requestID, i)
		}
		authz, options, err := authorizeFusionCall(ctx, finalReq, trGateway, secretCache, bearer, "fusion.final", idempotencyKey)
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr,
				"enclave.fusion_final_stream_authorize_failed request_log_id=%q request_id=%q model=%q attempt=%d error=%q\n",
				requestLogID, requestID, finalModel, i+1, err.Error(),
			)
			continue
		}
		anthropicReq, err := adapter.ToAnthropic(finalReq, finalReq.Model)
		if err != nil {
			if trGateway != nil && trGateway.Enabled() {
				_ = trGateway.Refund(ctx, authz, 400, "fusion_adapter_error", 0.001, finalReq.Metadata)
			}
			lastErr = err
			continue
		}
		committed, err := serveFusionFinalStreamingAttempt(ctx, conn, br, finalReq, anthropicReq, options, trGateway, authz, secretCache, time.Now(), originalInput, requestLogID, i == len(finalModels)-1)
		if committed {
			return nil
		}
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr,
				"enclave.fusion_final_stream_failed request_log_id=%q request_id=%q model=%q attempt=%d error=%q\n",
				requestLogID, requestID, finalModel, i+1, err.Error(),
			)
			continue
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return &adapter.AdapterError{Status: 502, Message: "trustedrouter/fusion final models produced no streaming answer", Context: "fusion.final"}
}

func serveFusionFinalStreamingAttempt(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	anthropicReq *types.AnthropicMessagesRequest,
	invokeOptions []llm.InvokeOptions,
	trGateway *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	secretCache *byokcache.Cache,
	requestStarted time.Time,
	originalInput any,
	requestLogID string,
	useLongLastCandidateBudget bool,
) (bool, error) {
	responseID := newRequestID()
	pr, pw := io.Pipe()
	selectedRoute := newSelectedRouteTracker()
	go invokeProviderStream(ctx, br, req, anthropicReq, pw, invokeOptions, trGateway != nil && trGateway.Enabled(), authorization, selectedRoute, requestLogID, useLongLastCandidateBudget)

	first := make([]byte, 4096)
	var n int
	var err error
	for n == 0 && err == nil {
		n, err = pr.Read(first)
	}
	if err != nil {
		if trGateway != nil && trGateway.Enabled() {
			_ = trGateway.Refund(ctx, authorization, 502, "provider_error", time.Since(requestStarted).Seconds(), req.Metadata)
		}
		_ = pr.Close()
		return false, err
	}
	streamModel := selectedRoute.Model(req.Model, authorization)
	if streamModel != "" {
		req.Model = streamModel
	}
	if err := writeResponseHead(conn, 200, "text/event-stream"); err != nil {
		_ = pr.Close()
		return true, err
	}

	chunkW := newChunkedWriter(conn)
	defer chunkW.Close()
	statsW := newStreamStatsWriter(chunkW)
	reader := io.MultiReader(bytes.NewReader(first[:n]), pr)
	result, err := adapter.TransformStreamCaptureWithOptions(reader, statsW, responseID, req.Model, chatIncludeUsage(req))
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.transform_stream_failed model=%q err=%v\n", req.Model, err)
		if trGateway != nil && trGateway.Enabled() {
			_ = trGateway.Refund(ctx, authorization, 502, "provider_error", time.Since(requestStarted).Seconds(), req.Metadata)
		}
		if statsW.BytesWritten() == 0 {
			_ = writeStreamingProviderError(statsW, "chat.completions", responseID, req.Model)
		}
		return true, err
	}
	inputTokens, outputTokens, usageEstimated := realOrEstimatedTokens(
		result,
		trustedrouter.EstimateInputTokens(req),
		trustedrouter.EstimateOutputTokens(adapter.ResponsesOutputForUsage(result)),
	)
	usage := trustedrouter.Usage{
		RequestID:         responseID,
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		ElapsedSeconds:    maxDurationSeconds(time.Since(requestStarted), 0.001),
		FirstTokenSeconds: statsW.FirstWriteSeconds(requestStarted),
		UsageEstimated:    usageEstimated,
		FinishReason:      result.FinishReason,
		Streamed:          true,
		RouteType:         "fusion.final",
		SelectedModel:     selectedRoute.Model(req.Model, authorization),
		SelectedEndpoint:  selectedRoute.Endpoint("", authorization),
		User:              req.User,
		SessionID:         req.SessionID,
		Trace:             req.Trace,
		Metadata:          req.Metadata,
	}
	applyCacheUsage(&usage, result)
	if _, err := settleAndBroadcast(ctx, trGateway, authorization, secretCache, usage, req, originalInput, adapter.ResponsesOutputForUsage(result)); err != nil {
		fmt.Fprintf(os.Stderr,
			"enclave.stream_settle_failed request_log_id=%q request_id=%q model=%q route_type=%q err=%v\n",
			requestLogID,
			responseID,
			req.Model,
			"fusion.final",
			err,
		)
		settlementRetries.Enqueue(settlementRetryJob{
			trGateway:     trGateway,
			authorization: authorization,
			secretCache:   secretCache,
			usage:         usage,
			req:           req,
			originalInput: originalInput,
			output:        adapter.ResponsesOutputForUsage(result),
			requestLogID:  requestLogID,
		})
	}
	return true, nil
}

func authorizeFusionCall(
	ctx context.Context,
	req *types.OpenAIChatRequest,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	routeType string,
	idempotencyKey string,
) (*trustedrouter.Authorization, []llm.InvokeOptions, error) {
	subReq := *req
	subReq.IdempotencyKey = idempotencyKey
	authz, err := trGateway.AuthorizeWithRoute(ctx, bearer, &subReq, routeType)
	if err != nil {
		return nil, nil, err
	}
	options, err := invokeOptionsForAuthorization(ctx, secretCache, authz)
	if err != nil {
		_ = trGateway.Refund(ctx, authz, 502, "byok_secret_error", 0.001, req.Metadata)
		return authz, nil, err
	}
	return authz, options, nil
}

func fusionPanelRequest(req *types.OpenAIChatRequest, model string, index int, maxCompletionTokens int) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = model
	out.Models = nil
	out.Stream = false
	// Give each panel member the caller's function tools (minus the
	// trustedrouter:fusion config entry) so they can actually propose tool calls.
	// Without this the panel was tool-blind and only ever produced text, so the
	// select strategies (first_non_refusal / first_success) could never surface a
	// tool call — a tool-use request silently lost its tools. The first
	// non-refusal panel member still wins as before; now that answer may itself
	// be a tool call, which passes straight through.
	out.Tools = stripFusionToolEntries(req.Tools)
	if len(out.Tools) == 0 {
		out.ToolChoice = nil
	}
	out.Plugins = nil
	out.ResponseFormat = nil
	out.MaxTokens = fusionInnerMaxTokens(req, maxCompletionTokens)
	system := fmt.Sprintf(
		"You are TrustedRouter Fusion panel member %d. Answer the user's request independently. Focus on correctness, cite uncertainty, and do not mention Fusion internals. Return only the visible answer; do not include chain-of-thought, hidden reasoning, or <think> blocks.",
		index+1,
	)
	if len(out.Tools) > 0 {
		system = fmt.Sprintf(
			"You are TrustedRouter Fusion panel member %d. Solve the user's request independently. If the next correct step is a tool call, emit the tool call directly instead of describing it; otherwise return only the visible answer. Focus on correctness, do not mention Fusion internals, and do not include chain-of-thought or <think> blocks.",
			index+1,
		)
	}
	out.Messages = prependSystem(req.Messages, system)
	out.Metadata = fusionMetadata(req.Metadata, "panel", model)
	return out
}

func fusionJudgeRequest(req *types.OpenAIChatRequest, model string, panel []fusionCallResult, maxCompletionTokens int) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = model
	out.Models = nil
	out.Stream = false
	out.Tools = nil
	out.ToolChoice = nil
	out.Plugins = nil
	out.ResponseFormat = map[string]any{"type": "json_object"}
	out.MaxTokens = fusionInnerMaxTokens(req, maxCompletionTokens)
	out.Messages = []types.OpenAIChatMessage{
		{
			Role:    "system",
			Content: "You are the TrustedRouter Fusion judge. Compare panel responses and return compact JSON with keys consensus, contradictions, partial_coverage, unique_insights, blind_spots, and final_guidance. Do not write the final answer. Return only JSON; do not include chain-of-thought, hidden reasoning, or <think> blocks.",
		},
		{
			Role:    "user",
			Content: fusionJudgePrompt(req, panel),
		},
	}
	out.Metadata = fusionMetadata(req.Metadata, "judge", model)
	return out
}

func fusionFinalRequest(req *types.OpenAIChatRequest, model string, judgeJSON string, panel []fusionCallResult) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = model
	out.Models = nil
	out.Stream = false
	out.Plugins = nil
	out.Tools = stripFusionToolEntries(out.Tools)
	out.Messages = append([]types.OpenAIChatMessage{}, req.Messages...)
	instruction := "TrustedRouter Fusion panel answers and judge analysis follow. Use the panel answers as the primary evidence and the judge analysis as guidance to write the final answer for the original request. Return only the final visible answer. Do not include chain-of-thought, hidden reasoning, analysis, scratchpad text, <think> blocks, or internal model names unless the user asked for methodology."
	if len(out.Tools) > 0 {
		instruction = "TrustedRouter Fusion panel answers and judge analysis follow. Continue solving the original task using the panel answers as primary evidence and the judge analysis as guidance. If the next correct action is a tool call, emit the tool call directly instead of describing it in text. Return visible text only when no tool call is needed. Do not include chain-of-thought, hidden reasoning, analysis, scratchpad text, <think> blocks, or internal model names unless the user asked for methodology."
	}
	out.Messages = append(out.Messages, types.OpenAIChatMessage{
		Role:    "user",
		Content: instruction + "\n\n" + fusionPanelEvidence(panel) + "\n\nJudge analysis JSON:\n" + judgeJSON,
	})
	out.Metadata = fusionMetadata(req.Metadata, "final", model)
	return out
}

func fusionPanelEvidence(panel []fusionCallResult) string {
	var b strings.Builder
	b.WriteString("Panel answers:\n")
	for i, item := range panel {
		model := item.Model
		if model == "" && item.Authorization != nil {
			model = item.Authorization.Model
		}
		text := strings.TrimSpace(item.Result.Text)
		// Surface each panel member's ACTUAL tool calls (name + arguments) so the
		// judge can compare them and the final synthesizer can fuse/emit the best
		// one. Previously these were flattened to a content-free "[returned tool
		// calls]" placeholder, which made synthesis blind to the panel's tool-use
		// decisions (the synthesizer then chose a tool call essentially alone).
		if tc := fusionToolCallsText(item.Result.ToolCalls); tc != "" {
			if text != "" {
				text += "\n" + tc
			} else {
				text = tc
			}
		}
		fmt.Fprintf(&b, "\n[%d] model=%s\n%s\n", i+1, model, text)
	}
	return b.String()
}

// fusionToolCallsText renders a panel member's tool calls as readable
// `name(arguments)` evidence for the judge and synthesizer prompts.
func fusionToolCallsText(calls []types.ToolCall) string {
	if len(calls) == 0 {
		return ""
	}
	parts := make([]string, 0, len(calls))
	for _, c := range calls {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			continue
		}
		args := strings.TrimSpace(c.Arguments)
		if args == "" {
			args = "{}"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", name, args))
	}
	if len(parts) == 0 {
		return ""
	}
	return "Proposed tool call(s): " + strings.Join(parts, ", ")
}

func fusionJudgePrompt(req *types.OpenAIChatRequest, panel []fusionCallResult) string {
	var b strings.Builder
	b.WriteString("Original request summary:\n")
	b.WriteString(chatMessagesText(req.Messages))
	b.WriteString("\n\nPanel responses:\n")
	b.WriteString(strings.TrimPrefix(fusionPanelEvidence(panel), "Panel answers:\n"))
	return b.String()
}

func chatMessagesText(messages []types.OpenAIChatMessage) string {
	var parts []string
	for _, message := range messages {
		text := strings.TrimSpace(types.ContentText(message.Content))
		if text == "" && types.ContentImageCount(message.Content) > 0 {
			text = "[non-text image content]"
		}
		if text == "" {
			continue
		}
		parts = append(parts, strings.ToUpper(message.Role)+": "+text)
	}
	return strings.Join(parts, "\n")
}

func prependSystem(messages []types.OpenAIChatMessage, system string) []types.OpenAIChatMessage {
	out := make([]types.OpenAIChatMessage, 0, len(messages)+1)
	out = append(out, types.OpenAIChatMessage{Role: "system", Content: system})
	out = append(out, messages...)
	return out
}

func cloneChatRequest(req *types.OpenAIChatRequest) *types.OpenAIChatRequest {
	out := *req
	out.Messages = append([]types.OpenAIChatMessage{}, req.Messages...)
	out.Models = append([]string{}, req.Models...)
	out.Tools = append([]any{}, req.Tools...)
	out.Plugins = append([]any{}, req.Plugins...)
	if req.Metadata != nil {
		out.Metadata = map[string]any{}
		for k, v := range req.Metadata {
			out.Metadata[k] = v
		}
	}
	if req.Trace != nil {
		out.Trace = map[string]any{}
		for k, v := range req.Trace {
			out.Trace[k] = v
		}
	}
	return &out
}

func fusionInnerMaxTokens(req *types.OpenAIChatRequest, configured int) *int {
	if configured > 0 {
		value := configured
		return &value
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		value := *req.MaxTokens
		if value > 2048 {
			value = 2048
		}
		return &value
	}
	value := 1200
	return &value
}

func fusionMetadata(input map[string]any, stage string, model string) map[string]any {
	out := map[string]any{}
	for k, v := range input {
		out[k] = v
	}
	out["trustedrouter_router"] = "trustedrouter/fusion"
	out["trustedrouter_fusion_stage"] = stage
	out["trustedrouter_fusion_model"] = model
	return out
}

func fusionUsageTotals(panel []fusionCallResult, judges []fusionCallResult, finals ...fusionCallResult) (int, int) {
	var inputs int
	var outputs int
	for _, final := range finals {
		inputs += final.InputTokens
		outputs += final.OutputTokens
	}
	for _, item := range panel {
		inputs += item.InputTokens
		outputs += item.OutputTokens
	}
	for _, item := range judges {
		inputs += item.InputTokens
		outputs += item.OutputTokens
	}
	if inputs < 1 {
		inputs = 1
	}
	if outputs < 1 {
		outputs = 1
	}
	return inputs, outputs
}

func fusionPanelUsageTotals(panel []fusionCallResult) (int, int) {
	inputs := 0
	outputs := 0
	for _, item := range panel {
		inputs += item.InputTokens
		outputs += item.OutputTokens
	}
	if inputs < 1 {
		inputs = 1
	}
	if outputs < 1 {
		outputs = 1
	}
	return inputs, outputs
}

func selectFusionPanelResult(panel []fusionCallResult, strategy string) (fusionCallResult, error) {
	if len(panel) == 0 {
		return fusionCallResult{}, &adapter.AdapterError{Status: 502, Message: "trustedrouter/fusion panel produced no responses", Context: "fusion.panel"}
	}
	if strategy == "first_non_refusal" {
		for _, item := range panel {
			if fusionPanelResultUsable(item) && !fusionLooksLikeRefusal(item.Result.Text) {
				return item, nil
			}
		}
	}
	for _, item := range panel {
		if fusionPanelResultUsable(item) {
			return item, nil
		}
	}
	return fusionCallResult{}, &adapter.AdapterError{Status: 502, Message: "trustedrouter/fusion panel produced no usable response", Context: "fusion.panel"}
}

func fusionPanelForSynthesis(panel []fusionCallResult, strategy string) ([]fusionCallResult, error) {
	if strategy != "synthesize_non_refusals" {
		return panel, nil
	}
	filtered := make([]fusionCallResult, 0, len(panel))
	for _, item := range panel {
		if fusionPanelResultUsable(item) && !fusionLooksLikeRefusal(item.Result.Text) {
			filtered = append(filtered, item)
		}
	}
	if len(filtered) == 0 {
		return nil, &adapter.AdapterError{Status: 502, Message: "trustedrouter/fusion panel produced no non-refusal responses", Context: "fusion.panel"}
	}
	return filtered, nil
}

func fusionFinalModels(config fusionConfig, requestedModel string, fallback string) ([]string, error) {
	raw := config.FinalModels
	if len(raw) == 0 {
		switch {
		case config.JudgeModel != "":
			raw = []string{config.JudgeModel}
		case requestedModel != "" && requestedModel != trustedRouterFusionModel:
			raw = []string{requestedModel}
		default:
			raw = []string{fallback}
		}
	}
	if len(raw) == 0 || len(raw) > 8 {
		return nil, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion final_models must contain 1-8 models", Context: "final_models"}
	}
	out := make([]string, 0, len(raw))
	for _, model := range raw {
		resolved := resolveFusionModelID(model)
		if resolved == "" {
			return nil, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion final_models must contain non-empty model ids", Context: "final_models"}
		}
		out = append(out, resolved)
	}
	return out, nil
}

func fusionJudgeModels(config fusionConfig, fallback string) ([]string, error) {
	raw := config.JudgeModels
	if len(raw) == 0 {
		if config.JudgeModel != "" {
			raw = []string{config.JudgeModel}
		} else {
			raw = []string{fallback}
		}
	}
	if len(raw) == 0 || len(raw) > 8 {
		return nil, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion judge_models must contain 1-8 models", Context: "judge_models"}
	}
	out := make([]string, 0, len(raw))
	for _, model := range raw {
		resolved := resolveFusionModelID(model)
		if resolved == "" {
			return nil, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion judge_models must contain non-empty model ids", Context: "judge_models"}
		}
		out = append(out, resolved)
	}
	return out, nil
}

func fusionPanelResultUsable(item fusionCallResult) bool {
	if item.Result.FinishReason == "error" || item.Result.FinishReason == "empty" {
		return false
	}
	if fusionPanelPlaceholder(item.Result.Text) {
		return false
	}
	return strings.TrimSpace(item.Result.Text) != "" || len(item.Result.ToolCalls) > 0
}

func fusionJudgeResultUsable(item fusionCallResult) bool {
	if item.Result.FinishReason == "error" || item.Result.FinishReason == "empty" {
		return false
	}
	if fusionPanelPlaceholder(item.Result.Text) {
		return false
	}
	return strings.TrimSpace(item.Result.Text) != ""
}

func fusionValidateFinalResult(result adapter.StreamResult) error {
	if strings.TrimSpace(result.Text) == "" && len(result.ToolCalls) == 0 {
		return &adapter.AdapterError{Status: 502, Message: "trustedrouter/fusion final model returned an empty visible answer", Context: "fusion.final"}
	}
	if strings.TrimSpace(result.Text) != "" && fusionLooksLikeRefusal(result.Text) {
		return &adapter.AdapterError{Status: 502, Message: "trustedrouter/fusion final model returned a refusal", Context: "fusion.final"}
	}
	return nil
}

func fusionPanelPlaceholder(text string) bool {
	trimmed := strings.TrimSpace(text)
	return strings.HasPrefix(trimmed, "[panel member ") &&
		(strings.Contains(trimmed, " failed before producing an answer:") ||
			strings.Contains(trimmed, " returned an empty answer;"))
}

func fusionLooksLikeRefusal(text string) bool {
	visible := strings.ToLower(fusionVisibleAnswer(text))
	visible = strings.ReplaceAll(visible, "’", "'")
	phrases := []string{
		"i can't",
		"i cannot",
		"i won't",
		"i'm unable",
		"cannot assist",
		"can't assist",
		"cannot help",
		"can't help",
		"cannot provide",
		"can't provide",
		"not able to provide",
		"not appropriate to provide",
		"i'm sorry",
		"sorry, but i can't",
	}
	for _, phrase := range phrases {
		if strings.Contains(visible, phrase) {
			return true
		}
	}
	return false
}

func selectedRouteModel(item fusionCallResult, fallback string) string {
	if item.Model != "" {
		return item.Model
	}
	if item.Authorization != nil && item.Authorization.Model != "" {
		return item.Authorization.Model
	}
	return fallback
}

func writeFusionError(ctx context.Context, conn io.Writer, trGateway *trustedrouter.Client, err error) {
	_ = ctx
	_ = trGateway
	var aerr *adapter.AdapterError
	if asAdapterErr(err, &aerr) {
		writeError(conn, aerr.Status, aerr.Message)
		return
	}
	writeError(conn, statusFromControlPlaneError(err), "fusion failed")
}

func resolveFusionModelID(model string) string {
	model = strings.TrimSpace(model)
	if mapped, ok := fusionModelAliases[strings.ToLower(model)]; ok {
		return mapped
	}
	return strings.TrimPrefix(model, "~")
}

func stripFusionToolEntries(tools []any) []any {
	if len(tools) == 0 {
		return nil
	}
	out := make([]any, 0, len(tools))
	for _, item := range tools {
		m, ok := item.(map[string]any)
		if !ok || strings.TrimSpace(stringValue(m["type"])) != trustedRouterFusionTool {
			out = append(out, item)
		}
	}
	return out
}

func fusionVisibleAnswer(text string) string {
	out := text
	for {
		lower := strings.ToLower(out)
		start := strings.Index(lower, "<think>")
		if start < 0 {
			break
		}
		endRelative := strings.Index(lower[start:], "</think>")
		if endRelative < 0 {
			out = out[:start]
			break
		}
		end := start + endRelative + len("</think>")
		out = out[:start] + out[end:]
	}
	return strings.TrimSpace(out)
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return ""
	}
}

func stringList(value any, context string) ([]string, error) {
	raw, ok := value.([]any)
	if !ok {
		return nil, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion list fields must be arrays", Context: context}
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		value := strings.TrimSpace(stringValue(item))
		if value == "" {
			return nil, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion model ids must be strings", Context: context}
		}
		out = append(out, value)
	}
	return out, nil
}

func intField(raw map[string]any, name string) (int, bool, error) {
	value, ok := raw[name]
	if !ok || value == nil {
		return 0, false, nil
	}
	switch v := value.(type) {
	case float64:
		if v != float64(int(v)) {
			return 0, true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion integer field must be an integer", Context: name}
		}
		return int(v), true, nil
	case int:
		return v, true, nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion integer field must be an integer", Context: name}
		}
		return int(n), true, nil
	default:
		return 0, true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/fusion integer field must be an integer", Context: name}
	}
}
