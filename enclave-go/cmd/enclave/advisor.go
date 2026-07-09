package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
const trustedRouterSocrates11Model = "trustedrouter/socrates-1.1"
const trustedRouterSocratesModel = "trustedrouter/socrates"
const trustedRouterAdvisorModel = "trustedrouter/advisor"
const trustedRouterAristotle10Model = "trustedrouter/aristotle-1.0"
const trustedRouterAristotle11Model = "trustedrouter/aristotle-1.1"
const trustedRouterAristotleModel = "trustedrouter/aristotle"
const trustedRouterPlato10Model = "trustedrouter/plato-1.0"
const trustedRouterPlatoModel = "trustedrouter/plato"
const trustedRouterPlatoPro10Model = "trustedrouter/plato-pro-1.0"
const trustedRouterPlatoProModel = "trustedrouter/plato-pro"
const trustedRouterSocratesPro10Model = "trustedrouter/socrates-pro-1.0"
const trustedRouterSocratesProModel = "trustedrouter/socrates-pro"
const trustedRouterSocratesProPlus10Model = "trustedrouter/socrates-pro-plus-1.0"
const trustedRouterSocratesProPlusModel = "trustedrouter/socrates-pro-plus"
const trustedRouterOpenPatcherA1Model = "trustedrouter/openpatcher-a1"
const trustedRouterOpenPatcherFast1Model = "trustedrouter/openpatcher-fast1"
const trustedRouterOpenPatcherG1Model = "trustedrouter/openpatcher-g1"
const trustedRouterAthenaModel = "trustedrouter/athena"
const trustedRouterAdvisorTool = "trustedrouter:advisor"
const advisorAdviceToolName = "_trustedrouter_get_advice"

const defaultOrchestrationDepth = 2
const maxOrchestrationDepth = 4
const defaultAdvisorAdviceCalls = 1
const maxAdvisorAdviceCalls = 3
const minAdvisorMaxTokens = 64
const defaultAdvisorMaxTokens = 4096
const maxAdvisorMaxTokens = 8192
const defaultAdvisorWorkerTimeoutMS = 60000
const maxAdvisorWorkerTimeoutMS = 180000
const defaultAdvisorTimeoutMS = 90000
const maxAdvisorTimeoutMS = 180000

var defaultAdvisorWorkerModels = []string{
	"cerebras/gpt-oss-120b",
}

var socratesProPlusWorkerModels = []string{
	"xiaomi/mimo-v2.5-pro-ultraspeed",
	"minimax/minimax-m3",
	"z-ai/glm-5.2-fast",
	"deepseek/deepseek-v4-flash",
}

var defaultAdvisorModels = []string{
	trustedRouterSocratesPro10Model,
}

const fallbackAdvisorWorkerPrompt = `You are a TrustedRouter advisor worker.

You have access to one private advisor tool: _trustedrouter_get_advice.

This tool is expensive. Use it deliberately, not for routine work.

For complex tasks, ask advice at major strategy checkpoints: before a costly/broad approach, after repeated stalls, or when choosing between plausible methods. Use routine commands yourself.

Do not call the advisor for straightforward work:
- simple factual answers
- obvious code edits
- routine summarization or formatting
- cases where you can answer confidently from the conversation

Call the advisor when one of these is true:
- planning with a second model could materially improve the result
- you are genuinely unsure between multiple approaches
- the task has security, privacy, legal, compliance, billing, or production-risk implications
- your first approach appears to be failing
- the user's constraints conflict or are underspecified in a way that affects correctness
- a wrong answer would be costly and a second opinion would materially improve the result

Respect the advice budget. Usually make at most one advisor call in a turn. Do not ask repeatedly for reassurance.`

const fallbackAdvisorPrompt = `You are the private TrustedRouter advisor.

Review the conversation and give concise, generous, actionable guidance to the worker model. Do not answer the user directly. Point out risks, missing constraints, likely mistakes, and a better approach. Keep the advice focused enough for the worker to act on immediately.`

const fallbackAdvisorFinalPrompt = `The TrustedRouter worker model path failed.

Answer the user directly using the conversation context. Be concise, correct, and useful. Do not mention internal routing unless it is necessary to explain a limitation.`

type advisorConfig struct {
	Enabled              bool
	Depth                int
	DepthSet             bool
	WorkerModels         []string
	AdvisorModels        []string
	MaxAdviceCalls       int
	MaxAdviceCallsSet    bool
	AdvisorMaxTokens     int
	WorkerTimeoutMS      int
	AdvisorTimeoutMS     int
	AutoInitialAdvice    bool
	AutoInitialAdviceSet bool
	BuiltInWorkerPrompt  string
	BuiltInAdvisorPrompt string
	HidePublicMetadata   bool
	ProviderJurisdiction string
}

type advisorPromptBundle struct {
	Worker  string
	Advisor string
}

var advisorPromptMu sync.RWMutex
var advisorPromptCache advisorPromptBundle

func configureAdvisorPrompts(boot *types.BootstrapData) {
	if boot == nil {
		return
	}
	advisorPromptMu.Lock()
	defer advisorPromptMu.Unlock()
	advisorPromptCache = advisorPromptBundle{
		Worker:  strings.TrimSpace(boot.AdvisorWorkerPrompt),
		Advisor: strings.TrimSpace(boot.AdvisorPrompt),
	}
}

func advisorPresetForModel(model string) (advisorConfig, bool) {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case trustedRouterAdvisorModel:
		return advisorConfig{Enabled: true}, true
	case trustedRouterSocrates10Model:
		return advisorConfig{
			Enabled:       true,
			WorkerModels:  []string{"cerebras/gpt-oss-120b", "deepseek/deepseek-v4-flash"},
			AdvisorModels: []string{trustedRouterSocratesPro10Model},
		}, true
	case trustedRouterAristotle10Model:
		return advisorConfig{
			Enabled:       true,
			WorkerModels:  []string{"deepseek/deepseek-v4-flash"},
			AdvisorModels: []string{trustedRouterZeus10Model},
		}, true
	case trustedRouterAristotleModel, trustedRouterAristotle11Model:
		return advisorConfig{
			Enabled:       true,
			WorkerModels:  []string{"z-ai/glm-5.2-fast", "z-ai/glm-5.2"},
			AdvisorModels: []string{trustedRouterZeus10Model},
		}, true
	case trustedRouterPlato10Model, trustedRouterPlatoModel:
		return advisorConfig{
			Enabled:       true,
			WorkerModels:  []string{"deepseek/deepseek-v4-flash"},
			AdvisorModels: []string{trustedRouterPlatoPro10Model},
		}, true
	case trustedRouterPlatoPro10Model, trustedRouterPlatoProModel:
		return advisorConfig{
			Enabled:       true,
			WorkerModels:  []string{"z-ai/glm-5.2"},
			AdvisorModels: []string{trustedRouterPrometheus101MModel},
		}, true
	case trustedRouterSocratesPro10Model, trustedRouterSocratesProModel:
		return advisorConfig{
			Enabled:       true,
			WorkerModels:  []string{"cerebras/zai-glm-4.7"},
			AdvisorModels: []string{trustedRouterSocratesProPlus10Model},
		}, true
	case trustedRouterSocratesModel, trustedRouterSocrates11Model, trustedRouterSocratesProPlus10Model, trustedRouterSocratesProPlusModel:
		return advisorConfig{
			Enabled:       true,
			WorkerModels:  append([]string(nil), socratesProPlusWorkerModels...),
			AdvisorModels: []string{trustedRouterZeus10Model},
		}, true
	case trustedRouterOpenPatcherA1Model:
		return advisorConfig{
			Enabled:              true,
			WorkerModels:         []string{trustedRouterOpenPatcherS1Model},
			AdvisorModels:        []string{trustedRouterPrometheus10Model},
			ProviderJurisdiction: providerJurisdictionUS,
		}, true
	case trustedRouterOpenPatcherFast1Model:
		return advisorConfig{
			Enabled:              true,
			WorkerModels:         []string{"z-ai/glm-5.2-fast"},
			AdvisorModels:        []string{trustedRouterOpenPatcherA1Model},
			ProviderJurisdiction: providerJurisdictionUS,
		}, true
	case trustedRouterOpenPatcherG1Model:
		return openPatcherG1AdvisorConfig(false), true
	case trustedRouterAthenaModel:
		return advisorConfig{
			Enabled:              true,
			WorkerModels:         []string{"z-ai/glm-5.2-fast", "z-ai/glm-5.2"},
			AdvisorModels:        []string{trustedRouterZeus10MiniModel, fusionCodeKimi, fusionGeneralKimi},
			HidePublicMetadata:   true,
			ProviderJurisdiction: providerJurisdictionUS,
		}, true
	default:
		return advisorConfig{}, false
	}
}

func openPatcherG1AdvisorConfig(hidePublicMetadata bool) advisorConfig {
	return advisorConfig{
		Enabled:              true,
		WorkerModels:         []string{"z-ai/glm-5.2-fast", "z-ai/glm-5.2"},
		AdvisorModels:        []string{fusionCodeKimi, trustedRouterPrometheus101MModel},
		HidePublicMetadata:   hidePublicMetadata,
		ProviderJurisdiction: providerJurisdictionUS,
	}
}

func isAdvisorOrchestrationModel(model string) bool {
	_, ok := advisorPresetForModel(model)
	return ok
}

func isGenericAdvisorPrimitive(model string) bool {
	return strings.ToLower(strings.TrimSpace(model)) == trustedRouterAdvisorModel
}

func isOrchestrationModel(model string) bool {
	return isAdvisorOrchestrationModel(model) || isFusionModel(model) || isSubagentModel(model)
}

func maybeServeAdvisor(
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
	config, requested, err := advisorConfigForRequest(req)
	if err != nil {
		return true, err
	}
	if !requested {
		return false, nil
	}
	if !config.Enabled {
		if isAdvisorOrchestrationModel(req.Model) {
			return true, &adapter.AdapterError{Status: 400, Message: "trustedrouter advisor models cannot be disabled without selecting a concrete model", Context: "trustedrouter:advisor.enabled"}
		}
		return false, nil
	}
	if trGateway == nil || !trGateway.Enabled() {
		return true, &adapter.AdapterError{Status: 503, Message: "trustedrouter/advisor requires the TrustedRouter control plane", Context: "trustedrouter/advisor"}
	}
	if err := validateGenericAdvisorConfig(config, req.Model); err != nil {
		return true, err
	}
	if err := normalizeAdvisorConfig(&config, req); err != nil {
		return true, err
	}
	forceProviderJurisdiction(req, config.ProviderJurisdiction)
	if err := rejectAdvisorToolCollision(req.Tools, req.ToolChoice); err != nil {
		return true, err
	}
	config.BuiltInWorkerPrompt, config.BuiltInAdvisorPrompt = advisorBuiltInPrompts()
	if advisorPromptsRequired() && (config.BuiltInWorkerPrompt == "" || config.BuiltInAdvisorPrompt == "") {
		return true, &adapter.AdapterError{Status: 503, Message: "trustedrouter/advisor prompt secrets are not configured", Context: "trustedrouter/advisor.prompts"}
	}
	if config.BuiltInWorkerPrompt == "" {
		config.BuiltInWorkerPrompt = fallbackAdvisorWorkerPrompt
	}
	if config.BuiltInAdvisorPrompt == "" {
		config.BuiltInAdvisorPrompt = fallbackAdvisorPrompt
	}

	workerModelsLog := strings.Join(config.WorkerModels, ",")
	advisorModelsLog := strings.Join(config.AdvisorModels, ",")
	if config.HidePublicMetadata {
		workerModelsLog = "[hidden]"
		advisorModelsLog = "[hidden]"
	}
	fmt.Fprintf(os.Stderr,
		"advisor.request_start request_log_id=%q model=%q depth_initial=%d max_get_advice_calls=%d worker_models=%q advisor_models=%q\n",
		requestLogID, req.Model, config.Depth, config.MaxAdviceCalls, workerModelsLog, advisorModelsLog,
	)
	if req.Stream {
		serveAdvisorStreaming(ctx, conn, br, req, config, trGateway, secretCache, bearer, originalInput, requestLogID)
	} else {
		serveAdvisorNonStreaming(ctx, conn, br, req, config, trGateway, secretCache, bearer, originalInput, requestLogID)
	}
	return true, nil
}

func validateGenericAdvisorConfig(config advisorConfig, model string) error {
	if !isGenericAdvisorPrimitive(model) {
		return nil
	}
	if len(config.WorkerModels) == 0 || len(config.AdvisorModels) == 0 {
		return &adapter.AdapterError{
			Status:  400,
			Message: "trustedrouter/advisor requires explicit worker_models and advisor_models; use trustedrouter/socrates-1.0 or another named model for a preset",
			Context: "trustedrouter:advisor",
		}
	}
	return nil
}

func advisorConfigForRequest(req *types.OpenAIChatRequest) (advisorConfig, bool, error) {
	config := advisorConfig{Enabled: true}
	requested := isAdvisorOrchestrationModel(req.Model)
	if preset, ok := advisorPresetForModel(req.Model); ok {
		config = mergeAdvisorConfig(config, preset)
	}
	if req.Depth != nil {
		config.Depth = *req.Depth
		config.DepthSet = true
	}
	cleanTools, toolConfig, toolRequested, err := advisorConfigFromTools(req.Tools)
	if err != nil {
		return advisorConfig{}, true, err
	}
	if toolRequested {
		config = mergeAdvisorConfig(config, toolConfig)
		requested = true
		req.Tools = cleanTools
	}
	return config, requested, nil
}

func advisorConfigFromTools(tools []any) ([]any, advisorConfig, bool, error) {
	if len(tools) == 0 {
		return tools, advisorConfig{}, false, nil
	}
	clean := make([]any, 0, len(tools))
	config := advisorConfig{Enabled: true}
	var requested bool
	for _, item := range tools {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, advisorConfig{}, false, &adapter.AdapterError{Status: 400, Message: "tool must be an object", Context: "tools"}
		}
		toolType := strings.TrimSpace(stringValue(m["type"]))
		if strings.ToLower(toolType) != trustedRouterAdvisorTool {
			clean = append(clean, item)
			continue
		}
		params, err := fusionParametersMap(m["parameters"], "tools.parameters")
		if err != nil {
			return nil, advisorConfig{}, true, err
		}
		parsed, err := parseAdvisorParameters(params)
		if err != nil {
			return nil, advisorConfig{}, true, err
		}
		config = mergeAdvisorConfig(config, parsed)
		requested = true
	}
	return clean, config, requested, nil
}

func parseAdvisorParameters(raw map[string]any) (advisorConfig, error) {
	config := advisorConfig{Enabled: true}
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
			config.MaxAdviceCallsSet = true
			break
		}
	}
	if n, ok, err := intField(raw, "advisor_max_tokens"); err != nil {
		return config, err
	} else if ok {
		config.AdvisorMaxTokens = n
	}
	if n, ok, err := intField(raw, "worker_timeout_ms"); err != nil {
		return config, err
	} else if ok {
		config.WorkerTimeoutMS = n
	}
	if n, ok, err := intField(raw, "advisor_timeout_ms"); err != nil {
		return config, err
	} else if ok {
		config.AdvisorTimeoutMS = n
	}
	if auto, ok, err := boolField(raw, "auto_initial_advice"); err != nil {
		return config, err
	} else if ok {
		config.AutoInitialAdvice = auto
		config.AutoInitialAdviceSet = true
	}
	return config, nil
}

func boolField(raw map[string]any, name string) (bool, bool, error) {
	value, ok := raw[name]
	if !ok || value == nil {
		return false, false, nil
	}
	valueBool, ok := value.(bool)
	if !ok {
		return false, true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor boolean field must be boolean", Context: name}
	}
	return valueBool, true, nil
}

func mergeAdvisorConfig(base, override advisorConfig) advisorConfig {
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
	if override.MaxAdviceCallsSet {
		base.MaxAdviceCalls = override.MaxAdviceCalls
		base.MaxAdviceCallsSet = true
	}
	if override.AdvisorMaxTokens != 0 {
		base.AdvisorMaxTokens = override.AdvisorMaxTokens
	}
	if override.WorkerTimeoutMS != 0 {
		base.WorkerTimeoutMS = override.WorkerTimeoutMS
	}
	if override.AdvisorTimeoutMS != 0 {
		base.AdvisorTimeoutMS = override.AdvisorTimeoutMS
	}
	if override.AutoInitialAdviceSet {
		base.AutoInitialAdvice = override.AutoInitialAdvice
		base.AutoInitialAdviceSet = true
	}
	if override.HidePublicMetadata {
		base.HidePublicMetadata = true
	}
	if override.ProviderJurisdiction != "" {
		base.ProviderJurisdiction = override.ProviderJurisdiction
	}
	return base
}

func normalizeAdvisorConfig(config *advisorConfig, req *types.OpenAIChatRequest) error {
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
		config.WorkerModels = append([]string(nil), defaultAdvisorWorkerModels...)
	}
	if len(config.WorkerModels) == 0 || len(config.WorkerModels) > 8 {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor worker_models must contain 1-8 models", Context: "worker_models"}
	}
	if len(config.AdvisorModels) == 0 {
		config.AdvisorModels = append([]string(nil), defaultAdvisorModels...)
	}
	if len(config.AdvisorModels) == 0 || len(config.AdvisorModels) > 8 {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor advisor_models must contain 1-8 models", Context: "advisor_models"}
	}
	if !config.MaxAdviceCallsSet {
		config.MaxAdviceCalls = defaultAdvisorAdviceCalls
	}
	if config.MaxAdviceCalls < 0 || config.MaxAdviceCalls > maxAdvisorAdviceCalls {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor max_get_advice_calls must be between 0 and 3", Context: "max_get_advice_calls"}
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 && *req.MaxTokens < minAdvisorMaxTokens {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor max_tokens must be at least 64", Context: "max_tokens"}
	}
	if config.AdvisorMaxTokens == 0 {
		config.AdvisorMaxTokens = defaultAdvisorMaxTokens
	}
	if config.AdvisorMaxTokens < 1 || config.AdvisorMaxTokens > maxAdvisorMaxTokens {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor advisor_max_tokens must be between 1 and 8192", Context: "advisor_max_tokens"}
	}
	if config.WorkerTimeoutMS == 0 {
		config.WorkerTimeoutMS = defaultAdvisorWorkerTimeoutMS
	}
	if config.WorkerTimeoutMS < 1000 || config.WorkerTimeoutMS > maxAdvisorWorkerTimeoutMS {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor worker_timeout_ms must be between 1000 and 180000", Context: "worker_timeout_ms"}
	}
	if config.AdvisorTimeoutMS == 0 {
		config.AdvisorTimeoutMS = defaultAdvisorTimeoutMS
	}
	if config.AdvisorTimeoutMS < 1000 || config.AdvisorTimeoutMS > maxAdvisorTimeoutMS {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor advisor_timeout_ms must be between 1000 and 180000", Context: "advisor_timeout_ms"}
	}
	for i, model := range config.WorkerModels {
		resolved := resolveFusionModelID(model)
		if resolved == "" || isAdvisorOrchestrationModel(resolved) {
			return &adapter.AdapterError{Status: 400, Message: "trustedrouter/advisor worker_models must be concrete or synth model ids", Context: "worker_models"}
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

func advisorBuiltInPrompts() (string, string) {
	advisorPromptMu.RLock()
	defer advisorPromptMu.RUnlock()
	return advisorPromptCache.Worker, advisorPromptCache.Advisor
}

func advisorPromptsRequired() bool {
	return os.Getenv("TR_REQUIRE_ADVISOR_PROMPTS") == "1" ||
		(os.Getenv("QUILL_GCP_PROJECT_ID") != "" && os.Getenv("TR_ALLOW_DEFAULT_ADVISOR_PROMPTS") != "1")
}

func serveAdvisorNonStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config advisorConfig,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestLogID string,
) {
	requestStarted := time.Now()
	requestID := newRequestID()
	final, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, err := runAdvisor(ctx, br, req, config, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, nil, 0, nil)
	if err != nil {
		if config.HidePublicMetadata {
			writeErrorWithSourceHeaders(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "model request failed"), "router", retryHeadersFromControlPlaneError(err))
			return
		}
		writeFusionError(ctx, conn, trGateway, err)
		return
	}
	totalIn, totalOut := advisorUsageTotals(workerAttempts, advisorAttempts)
	selectedModel := final.Model
	if selectedModel == "" {
		selectedModel = config.WorkerModels[0]
	}
	responseModel := requestOrchestrationResponseModel(req, selectedModel)
	var body bytes.Buffer
	if err := writeAdvisorChatCompletionResponse(
		&body,
		requestID,
		responseModel,
		final.Result.Text,
		adapter.JoinThinking(final.Result.Thinking),
		final.Result.ToolCalls,
		totalIn,
		totalOut,
		advisorPublicStreamUsage(config, totalIn, totalOut, workerAttempts, advisorAttempts),
		time.Now().Unix(),
		final.Result.FinishReason,
		advisorResponseDetails(config, workerAttempts, advisorAttempts, responseModel, selectedModel, adviceCalls, budgetExhausted),
	); err != nil {
		writeError(conn, 500, "advisor response encoding error")
		return
	}
	fmt.Fprintf(os.Stderr,
		"advisor.request_end request_log_id=%q request_id=%q mode=nonstream outcome=%q advice_call_count=%d advice_budget_exhausted=%t selected_model=%q elapsed_ms=%d\n",
		requestLogID, requestID, "success", adviceCalls, budgetExhausted, responseModel, time.Since(requestStarted).Milliseconds(),
	)
	writeJSONResponse(conn, 200, body.Bytes())
}

func serveAdvisorStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config advisorConfig,
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
	var streamW io.Writer = statsW
	var observer func(stage string, index int, model string) adapter.StreamObserver
	if config.HidePublicMetadata {
		streamW = nil
	} else {
		_ = writeAdvisorStreamEvent(statsW, requestID, req.Model, created, map[string]any{
			"event":                "advisor.started",
			"depth_initial":        config.Depth,
			"max_get_advice_calls": config.MaxAdviceCalls,
		})
		observer = func(stage string, index int, model string) adapter.StreamObserver {
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
				_ = writeAdvisorStreamEvent(statsW, requestID, req.Model, created, event)
			}
		}
	}
	final, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, err := runAdvisor(ctx, br, req, config, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, streamW, created, observer)
	if err != nil {
		if config.HidePublicMetadata {
			_ = writeHiddenAdvisorStreamError(statsW, requestID, req.Model, created)
		} else {
			_ = writeAdvisorStreamError(statsW, requestID, req.Model, created, err, workerAttempts, advisorAttempts)
		}
		return
	}
	selectedModel := final.Model
	if selectedModel == "" {
		selectedModel = config.WorkerModels[0]
	}
	responseModel := requestOrchestrationResponseModel(req, selectedModel)
	if len(final.Result.ToolCalls) > 0 {
		if !config.HidePublicMetadata {
			_ = writeAdvisorStreamEvent(statsW, requestID, responseModel, created, map[string]any{
				"event":      "advisor.tool_calls",
				"tool_calls": final.Result.ToolCalls,
			})
		}
		if err := writeFusionStreamToolCalls(statsW, requestID, responseModel, created, final.Result.ToolCalls); err != nil {
			return
		}
	} else if text := strings.TrimSpace(final.Result.Text); text != "" {
		_ = writeFusionStreamDelta(statsW, requestID, responseModel, created, map[string]any{"content": text}, "")
	}
	if err := writeFusionStreamDelta(statsW, requestID, responseModel, created, map[string]any{}, fusionFinishReason(final.Result)); err != nil {
		return
	}
	if chatIncludeUsage(req) {
		totalIn, totalOut := advisorUsageTotals(workerAttempts, advisorAttempts)
		usage := final
		usage.InputTokens = totalIn
		usage.OutputTokens = totalOut
		usage.Result.Usage = advisorPublicStreamUsage(config, totalIn, totalOut, workerAttempts, advisorAttempts)
		details := advisorResponseDetails(config, workerAttempts, advisorAttempts, responseModel, selectedModel, adviceCalls, budgetExhausted)
		providerUsage := advisorPublicProviderUsage(details)
		if config.HidePublicMetadata {
			_ = writeHiddenAdvisorStreamUsage(statsW, requestID, responseModel, created, usage, advisorTotalCostMicrodollars(workerAttempts, advisorAttempts), providerUsage)
		} else {
			_ = writeFusionStreamUsage(statsW, requestID, responseModel, created, usage, advisorTotalCostMicrodollars(workerAttempts, advisorAttempts), providerUsage)
		}
	}
	_, _ = statsW.Write([]byte("data: [DONE]\n\n"))
	fmt.Fprintf(os.Stderr,
		"advisor.request_end request_log_id=%q request_id=%q mode=stream outcome=%q advice_call_count=%d advice_budget_exhausted=%t selected_model=%q elapsed_ms=%d\n",
		requestLogID, requestID, "success", adviceCalls, budgetExhausted, responseModel, time.Since(requestStarted).Milliseconds(),
	)
}

func runAdvisor(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config advisorConfig,
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
	allWorkerAttempts := make([]fusionCallResult, 0, len(config.WorkerModels))
	allAdvisorAttempts := make([]fusionCallResult, 0, len(config.AdvisorModels))
	totalAdviceCalls := 0
	anyBudgetExhausted := false
	for i, workerModel := range config.WorkerModels {
		final, workers, advisors, adviceCalls, budgetExhausted, err := runAdvisorWorkerLoop(ctx, br, req, config, workerModel, i, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, streamW, streamCreated, observerFactory)
		allWorkerAttempts = append(allWorkerAttempts, workers...)
		allAdvisorAttempts = append(allAdvisorAttempts, advisors...)
		totalAdviceCalls += adviceCalls
		anyBudgetExhausted = anyBudgetExhausted || budgetExhausted
		if err == nil {
			return final, allWorkerAttempts, allAdvisorAttempts, totalAdviceCalls, anyBudgetExhausted, nil
		}
		lastErr = err
		fmt.Fprintf(os.Stderr,
			"advisor.worker_attempt request_log_id=%q request_id=%q model=%q attempt=%d outcome=%q error=%q\n",
			requestLogID, requestID, workerModel, i+1, "error", err.Error(),
		)
		if streamW != nil {
			_ = writeAdvisorStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event": "worker.failed",
				"stage": "worker",
				"index": i,
				"model": workerModel,
				"error": err.Error(),
			})
		}
	}
	if lastErr != nil {
		final, advisors, err := runAdvisorFinal(ctx, br, req, config, req.Messages, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, streamW, streamCreated, observerFactory)
		allAdvisorAttempts = append(allAdvisorAttempts, advisors...)
		if err == nil {
			return final, allWorkerAttempts, allAdvisorAttempts, totalAdviceCalls, anyBudgetExhausted, nil
		}
		return fusionCallResult{}, allWorkerAttempts, allAdvisorAttempts, totalAdviceCalls, anyBudgetExhausted, lastErr
	}
	return fusionCallResult{}, allWorkerAttempts, allAdvisorAttempts, totalAdviceCalls, anyBudgetExhausted, &adapter.AdapterError{Status: 502, Message: "trustedrouter/advisor worker models produced no response", Context: "advisor.worker"}
}

func runAdvisorWorkerLoop(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config advisorConfig,
	workerModel string,
	workerIndex int,
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
	workerConfig := config
	if advisorShouldAutoInitialAdvice(config) {
		adviceCalls++
		fmt.Fprintf(os.Stderr,
			"advisor.advice_call request_log_id=%q request_id=%q worker_model=%q call_index=%d depth_remaining=%d advisor_models=%q auto_initial=%t\n",
			requestLogID, requestID, workerModel, adviceCalls, config.Depth, strings.Join(config.AdvisorModels, ","), true,
		)
		if streamW != nil {
			_ = writeAdvisorStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event":        "advice.started",
				"stage":        "advisor",
				"index":        adviceCalls - 1,
				"auto_initial": true,
			})
		}
		adviceText, attempts := runAdvisorAdvice(ctx, br, req, config, messages, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, streamW, streamCreated, observerFactory)
		advisorAttempts = append(advisorAttempts, attempts...)
		if adviceText = strings.TrimSpace(adviceText); adviceText != "" {
			workerConfig.BuiltInWorkerPrompt = strings.TrimSpace(workerConfig.BuiltInWorkerPrompt + "\n\n" + advisorInitialAdviceMessage(adviceText))
		}
	}
	allowAdviceTool := adviceCalls < config.MaxAdviceCalls
	for turn := 0; turn < config.MaxAdviceCalls+3; turn++ {
		if streamW != nil {
			_ = writeAdvisorStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event": "worker.started",
				"stage": "worker",
				"index": turn,
				"model": workerModel,
			})
		}
		workerReq := advisorWorkerRequest(req, workerModel, messages, workerConfig, allowAdviceTool && !isFusionModel(workerModel))
		var worker fusionCallResult
		var err error
		workerTimeout := advisorWorkerAttemptTimeout(config)
		if isFusionModel(workerModel) {
			worker, err = runAdvisorFusionWorkerRequest(ctx, br, workerReq, config, workerModel, trGateway, secretCache, bearer, fmt.Sprintf("%s:worker:%d:%d", requestID, workerIndex, turn), requestLogID, originalInput)
		} else {
			var observer adapter.StreamObserver
			if observerFactory != nil {
				observer = observerFactory("worker", turn, workerModel)
			}
			worker, err = runFusionCallObservedWithInvokeTimeout(ctx, br, workerReq, trGateway, secretCache, bearer, "advisor.worker", fmt.Sprintf("%s:worker:%d:%d", requestID, workerIndex, turn), requestLogID, originalInput, false, observer, streamW != nil, workerTimeout)
		}
		if err != nil {
			return fusionCallResult{}, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, err
		}
		worker.RouteType = "advisor.worker"
		workerAttempts = append(workerAttempts, worker)
		if streamW != nil {
			_ = writeAdvisorStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event":  "worker.done",
				"stage":  "worker",
				"index":  turn,
				"model":  workerModel,
				"detail": advisorSafeCallDetails(worker, true),
			})
		}
		adviceCall, hasAdvice := advisorAdviceToolCall(worker.Result.ToolCalls)
		if !hasAdvice {
			if strings.TrimSpace(worker.Result.Text) == "" && len(worker.Result.ToolCalls) == 0 {
				return fusionCallResult{}, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, &adapter.AdapterError{Status: 502, Message: "trustedrouter/advisor worker returned an empty response", Context: "advisor.worker"}
			}
			return worker, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, nil
		}
		if adviceCalls >= config.MaxAdviceCalls {
			budgetExhausted = true
			fmt.Fprintf(os.Stderr,
				"advisor.advice_budget_exhausted request_log_id=%q request_id=%q worker_model=%q depth_remaining=%d\n",
				requestLogID, requestID, workerModel, config.Depth,
			)
			messages = append(messages, advisorAssistantToolMessage(adviceCall), types.OpenAIChatMessage{
				Role:       "tool",
				Name:       advisorAdviceToolName,
				ToolCallID: advisorToolCallID(adviceCall, turn),
				Content:    "Advice budget exhausted. Answer now.",
			})
			allowAdviceTool = false
			continue
		}
		adviceCalls++
		fmt.Fprintf(os.Stderr,
			"advisor.advice_call request_log_id=%q request_id=%q worker_model=%q call_index=%d depth_remaining=%d advisor_models=%q\n",
			requestLogID, requestID, workerModel, adviceCalls, config.Depth, strings.Join(config.AdvisorModels, ","),
		)
		if streamW != nil {
			_ = writeAdvisorStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event": "advice.started",
				"stage": "advisor",
				"index": adviceCalls - 1,
			})
		}
		adviceText, attempts := runAdvisorAdvice(ctx, br, req, config, messages, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, streamW, streamCreated, observerFactory)
		advisorAttempts = append(advisorAttempts, attempts...)
		if strings.TrimSpace(adviceText) == "" {
			adviceText = "Advisor unavailable. Continue with your best answer now."
		}
		messages = append(messages, advisorAssistantToolMessage(adviceCall), types.OpenAIChatMessage{
			Role:       "tool",
			Name:       advisorAdviceToolName,
			ToolCallID: advisorToolCallID(adviceCall, turn),
			Content:    adviceText,
		})
	}
	return fusionCallResult{}, workerAttempts, advisorAttempts, adviceCalls, budgetExhausted, &adapter.AdapterError{Status: 502, Message: "trustedrouter/advisor did not complete after advice", Context: "advisor"}
}

func advisorWorkerAttemptTimeout(config advisorConfig) time.Duration {
	if config.WorkerTimeoutMS <= 0 {
		return 0
	}
	return time.Duration(config.WorkerTimeoutMS) * time.Millisecond
}

func runAdvisorAdvice(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config advisorConfig,
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
	if len(config.AdvisorModels) == 0 {
		return "", nil
	}
	emitter := newAdvisorStreamEmitter(streamW, requestID, req.Model, streamCreated)
	results := make([]advisorAdviceModelResult, len(config.AdvisorModels))
	var wg sync.WaitGroup
	for i, advisorModel := range config.AdvisorModels {
		i, advisorModel := i, advisorModel
		wg.Add(1)
		go func() {
			defer wg.Done()
			emitter.Event(map[string]any{
				"event": "advisor.started",
				"stage": "advisor",
				"index": i,
				"model": advisorModel,
			})
			result, attempts, err := runAdvisorAdviceModel(ctx, br, req, config, advisorModel, i, messages, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, emitter, observerFactory)
			results[i] = advisorAdviceModelResult{
				Index:    i,
				Model:    advisorModel,
				Result:   result,
				Attempts: attempts,
				Err:      err,
			}
			if err != nil {
				fmt.Fprintf(os.Stderr,
					"advisor.advisor_failed request_log_id=%q request_id=%q model=%q attempt=%d error=%q\n",
					requestLogID, requestID, advisorModel, i+1, err.Error(),
				)
				emitter.Event(map[string]any{
					"event": "advisor.failed",
					"stage": "advisor",
					"index": i,
					"model": advisorModel,
					"error": err.Error(),
				})
				return
			}
			emitter.Event(map[string]any{
				"event":  "advisor.done",
				"stage":  "advisor",
				"index":  i,
				"model":  advisorModel,
				"detail": advisorSafeCallDetails(result, false),
			})
		}()
	}
	wg.Wait()

	attempts := make([]fusionCallResult, 0, len(config.AdvisorModels))
	texts := make([]advisorAdviceText, 0, len(config.AdvisorModels))
	var lastErr error
	for _, item := range results {
		attempts = append(attempts, item.Attempts...)
		if item.Err != nil {
			lastErr = item.Err
			continue
		}
		text := strings.TrimSpace(item.Result.Result.Text)
		if text == "" || fusionLooksLikeRefusal(text) {
			continue
		}
		texts = append(texts, advisorAdviceText{Index: item.Index, Model: item.Model, Text: text})
	}
	if lastErr != nil {
		fmt.Fprintf(os.Stderr,
			"advisor.advisor_unavailable request_log_id=%q request_id=%q error=%q\n",
			requestLogID, requestID, lastErr.Error(),
		)
	}
	return advisorPanelText(texts), attempts
}

type advisorAdviceModelResult struct {
	Index    int
	Model    string
	Result   fusionCallResult
	Attempts []fusionCallResult
	Err      error
}

type advisorAdviceText struct {
	Index int
	Model string
	Text  string
}

type advisorStreamEmitter struct {
	mu        sync.Mutex
	w         io.Writer
	requestID string
	model     string
	created   int64
}

func newAdvisorStreamEmitter(w io.Writer, requestID string, model string, created int64) *advisorStreamEmitter {
	if w == nil {
		return nil
	}
	return &advisorStreamEmitter{w: w, requestID: requestID, model: model, created: created}
}

func (e *advisorStreamEmitter) Event(event map[string]any) {
	if e == nil || e.w == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = writeAdvisorStreamEvent(e.w, e.requestID, e.model, e.created, event)
}

func (e *advisorStreamEmitter) Observer(stage string, index int, model string) adapter.StreamObserver {
	if e == nil {
		return nil
	}
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
		e.Event(event)
	}
}

func runAdvisorAdviceModel(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config advisorConfig,
	advisorModel string,
	advisorIndex int,
	messages []types.OpenAIChatMessage,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
	emitter *advisorStreamEmitter,
	observerFactory func(stage string, index int, model string) adapter.StreamObserver,
) (fusionCallResult, []fusionCallResult, error) {
	advisorMessages, attempts := advisorMaybeCompactMessages(ctx, br, req, config, advisorModel, advisorIndex, messages, trGateway, secretCache, bearer, requestID, requestLogID, originalInput)
	var result fusionCallResult
	var err error
	if isAdvisorOrchestrationModel(advisorModel) {
		result, err = runNestedAdvisor(ctx, br, req, config, advisorModel, advisorMessages, trGateway, secretCache, bearer, fmt.Sprintf("%s:advisor:%d", requestID, advisorIndex), requestLogID, originalInput, false)
	} else if isFusionModel(advisorModel) {
		result, err = runFusionAdvisor(ctx, br, req, config, advisorModel, advisorMessages, trGateway, secretCache, bearer, fmt.Sprintf("%s:advisor:%d", requestID, advisorIndex), requestLogID, originalInput)
	} else {
		advisorReq := advisorRequest(req, advisorModel, advisorMessages, config)
		var observer adapter.StreamObserver
		if emitter != nil {
			observer = emitter.Observer("advisor", advisorIndex, advisorModel)
		} else if observerFactory != nil {
			observer = observerFactory("advisor", advisorIndex, advisorModel)
		}
		timeout := time.Duration(config.AdvisorTimeoutMS) * time.Millisecond
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		result, err = runFusionCallObserved(attemptCtx, br, advisorReq, trGateway, secretCache, bearer, "advisor.advisor", fmt.Sprintf("%s:advisor:%d", requestID, advisorIndex), requestLogID, originalInput, false, observer, emitter != nil)
		cancel()
	}
	if err != nil {
		return result, attempts, err
	}
	result.RouteType = "advisor.advisor"
	attempts = append(attempts, result)
	return result, attempts, nil
}

func advisorPanelText(texts []advisorAdviceText) string {
	if len(texts) == 0 {
		return ""
	}
	if len(texts) == 1 {
		return strings.TrimSpace(texts[0].Text)
	}
	var b strings.Builder
	b.WriteString("TrustedRouter advisor panel returned these private guidance notes. Use all useful points, resolve conflicts yourself, then answer the user.\n")
	for _, item := range texts {
		fmt.Fprintf(&b, "\nAdvisor %d (%s):\n%s\n", item.Index+1, item.Model, strings.TrimSpace(item.Text))
	}
	return strings.TrimSpace(b.String())
}

func advisorMaybeCompactMessages(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config advisorConfig,
	advisorModel string,
	advisorIndex int,
	messages []types.OpenAIChatMessage,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
) ([]types.OpenAIChatMessage, []fusionCallResult) {
	if !advisorNeedsCompactedContext(advisorModel, messages, config) {
		return messages, nil
	}
	summaryModel := advisorContextSummaryModel(config)
	if summaryModel == "" {
		return messages, nil
	}
	summaryReq := advisorContextSummaryRequest(req, summaryModel, advisorModel, messages, config)
	summary, err := runFusionCallObserved(
		ctx,
		br,
		summaryReq,
		trGateway,
		secretCache,
		bearer,
		"advisor.context_summary",
		fmt.Sprintf("%s:advisor:%d:context-summary", requestID, advisorIndex),
		requestLogID,
		originalInput,
		false,
		nil,
		false,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"advisor.context_summary_failed request_log_id=%q request_id=%q summary_model=%q advisor_model=%q error=%q\n",
			requestLogID, requestID, summaryModel, advisorModel, err.Error(),
		)
		return messages, nil
	}
	summary.RouteType = "advisor.context_summary"
	text := strings.TrimSpace(summary.Result.Text)
	if text == "" {
		return messages, []fusionCallResult{summary}
	}
	compacted := []types.OpenAIChatMessage{{
		Role: "user",
		Content: fmt.Sprintf(
			"Compacted conversation context for shorter-context advisor %s. This summary was produced from the full conversation by %s.\n\n%s",
			advisorModel,
			summaryModel,
			text,
		),
	}}
	return compacted, []fusionCallResult{summary}
}

func advisorContextSummaryModel(config advisorConfig) string {
	for _, model := range config.WorkerModels {
		model = strings.TrimSpace(model)
		if model == "" || isAdvisorOrchestrationModel(model) || isFusionModel(model) {
			continue
		}
		return model
	}
	return ""
}

func advisorContextSummaryRequest(req *types.OpenAIChatRequest, summaryModel string, advisorModel string, messages []types.OpenAIChatMessage, config advisorConfig) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = summaryModel
	out.Models = nil
	forceFusionThroughputRouting(out)
	out.Stream = false
	out.Plugins = nil
	out.Tools = nil
	out.ToolChoice = nil
	out.ResponseFormat = nil
	maxTokens := config.AdvisorMaxTokens
	if maxTokens <= 0 || maxTokens > 4096 {
		maxTokens = 4096
	}
	out.MaxTokens = &maxTokens
	prompt := fmt.Sprintf(`Summarize the full conversation for a shorter-context advisor model: %s.

Preserve the user's goal, hard constraints, relevant code or error details, security/privacy requirements, and any partial conclusions.
Remove redundancy. Do not invent facts. Do not answer the user.
The next model will use only this summary to give private advice.`, advisorModel)
	out.Messages = prependSystem(messages, prompt)
	out.Metadata = advisorMetadata(out.Metadata, "context_summary", summaryModel, config)
	return out
}

func advisorNeedsCompactedContext(advisorModel string, messages []types.OpenAIChatMessage, config advisorConfig) bool {
	limit := advisorContextLimitTokens(advisorModel)
	if limit >= 1_000_000 {
		return false
	}
	usable := limit - config.AdvisorMaxTokens - 8_000
	if usable < 32_000 {
		usable = 32_000
	}
	return advisorEstimatedMessageTokens(messages) > usable
}

func advisorContextLimitTokens(model string) int {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case trustedRouterPrometheus101MModel,
		"minimax/minimax-m3",
		"xiaomi/mimo-v2.5-pro",
		"z-ai/glm-5.2",
		"deepseek/deepseek-v4-pro":
		return 1_048_576
	default:
		return 200_000
	}
}

func advisorEstimatedMessageTokens(messages []types.OpenAIChatMessage) int {
	chars := 0
	for _, message := range messages {
		if encoded, err := json.Marshal(message); err == nil {
			chars += len(encoded)
		} else {
			chars += len(message.Role) + len(types.ContentText(message.Content))
		}
	}
	if chars < 4 {
		return 1
	}
	return chars / 4
}

func runAdvisorFinal(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config advisorConfig,
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
) (fusionCallResult, []fusionCallResult, error) {
	attempts := make([]fusionCallResult, 0, len(config.AdvisorModels))
	var lastErr error
	for i, advisorModel := range config.AdvisorModels {
		if streamW != nil {
			_ = writeAdvisorStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event": "advisor_final.started",
				"stage": "advisor_final",
				"index": i,
				"model": advisorModel,
			})
		}
		var result fusionCallResult
		var err error
		if isAdvisorOrchestrationModel(advisorModel) {
			result, err = runNestedAdvisor(ctx, br, req, config, advisorModel, messages, trGateway, secretCache, bearer, fmt.Sprintf("%s:advisor-final:%d", requestID, i), requestLogID, originalInput, true)
		} else if isFusionModel(advisorModel) {
			result, err = runFusionAdvisorFinal(ctx, br, req, config, advisorModel, messages, trGateway, secretCache, bearer, fmt.Sprintf("%s:advisor-final:%d", requestID, i), requestLogID, originalInput)
		} else {
			advisorReq := advisorFinalRequest(req, advisorModel, messages, config)
			var observer adapter.StreamObserver
			if observerFactory != nil {
				observer = observerFactory("advisor_final", i, advisorModel)
			}
			timeout := time.Duration(config.AdvisorTimeoutMS) * time.Millisecond
			attemptCtx, cancel := context.WithTimeout(ctx, timeout)
			result, err = runFusionCallObserved(attemptCtx, br, advisorReq, trGateway, secretCache, bearer, "advisor.advisor_final", fmt.Sprintf("%s:advisor-final:%d", requestID, i), requestLogID, originalInput, false, observer, streamW != nil)
			cancel()
		}
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr,
				"advisor.advisor_final_failed request_log_id=%q request_id=%q model=%q attempt=%d error=%q\n",
				requestLogID, requestID, advisorModel, i+1, err.Error(),
			)
			continue
		}
		result.RouteType = "advisor.advisor_final"
		attempts = append(attempts, result)
		text := strings.TrimSpace(result.Result.Text)
		if text == "" || fusionLooksLikeRefusal(text) {
			lastErr = &adapter.AdapterError{Status: 502, Message: "trustedrouter/advisor fallback returned an empty or refused response", Context: "advisor.advisor_final"}
			continue
		}
		if streamW != nil {
			_ = writeAdvisorStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event":  "advisor_final.done",
				"stage":  "advisor_final",
				"index":  i,
				"model":  advisorModel,
				"detail": advisorSafeCallDetails(result, false),
			})
		}
		return result, attempts, nil
	}
	if lastErr != nil {
		return fusionCallResult{}, attempts, lastErr
	}
	return fusionCallResult{}, attempts, &adapter.AdapterError{Status: 502, Message: "trustedrouter/advisor fallback produced no response", Context: "advisor.advisor_final"}
}

func runNestedAdvisor(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config advisorConfig,
	advisorModel string,
	messages []types.OpenAIChatMessage,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
	finalAnswer bool,
) (fusionCallResult, error) {
	if config.Depth <= 0 {
		fmt.Fprintf(os.Stderr,
			"advisor.depth_blocked request_log_id=%q request_id=%q model=%q depth_remaining=%d\n",
			requestLogID, requestID, advisorModel, config.Depth,
		)
		return fusionCallResult{}, &adapter.AdapterError{Status: 400, Message: "trustedrouter orchestration depth exhausted", Context: "depth"}
	}
	childDepth := config.Depth - 1
	var advisorReq *types.OpenAIChatRequest
	if finalAnswer {
		advisorReq = advisorFinalRequest(req, advisorModel, messages, config)
	} else {
		advisorReq = advisorRequest(req, advisorModel, messages, config)
	}
	advisorReq.Depth = &childDepth
	childConfig, requested, err := advisorConfigForRequest(advisorReq)
	if err != nil {
		return fusionCallResult{}, err
	}
	if !requested {
		return fusionCallResult{}, &adapter.AdapterError{Status: 400, Message: "advisor model is not a supported orchestration model", Context: "advisor_model"}
	}
	if err := normalizeAdvisorConfig(&childConfig, advisorReq); err != nil {
		return fusionCallResult{}, err
	}
	childConfig.BuiltInWorkerPrompt = config.BuiltInWorkerPrompt
	childConfig.BuiltInAdvisorPrompt = config.BuiltInAdvisorPrompt
	final, workers, advisors, adviceCalls, budgetExhausted, err := runAdvisor(ctx, br, advisorReq, childConfig, trGateway, secretCache, bearer, requestID+":advisor", requestLogID, originalInput, nil, 0, nil)
	if err != nil {
		return fusionCallResult{}, err
	}
	final.Orchestration = map[string]any{
		"advisor": advisorResponseDetails(childConfig, workers, advisors, requestOrchestrationResponseModel(advisorReq, advisorModel), final.Model, adviceCalls, budgetExhausted),
	}
	totalIn, totalOut := advisorUsageTotals(workers, advisors)
	final.InputTokens = totalIn
	final.OutputTokens = totalOut
	final.Result.Usage = fusionAggregateStreamUsage(totalIn, totalOut, workers, advisors)
	return final, nil
}

func runFusionAdvisor(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config advisorConfig,
	advisorModel string,
	messages []types.OpenAIChatMessage,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
) (fusionCallResult, error) {
	advisorReq := advisorRequest(req, advisorModel, messages, config)
	return runFusionAdvisorRequest(ctx, br, advisorReq, config, advisorModel, trGateway, secretCache, bearer, requestID, requestLogID, originalInput)
}

func runFusionAdvisorFinal(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config advisorConfig,
	advisorModel string,
	messages []types.OpenAIChatMessage,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
) (fusionCallResult, error) {
	advisorReq := advisorFinalRequest(req, advisorModel, messages, config)
	return runFusionAdvisorRequest(ctx, br, advisorReq, config, advisorModel, trGateway, secretCache, bearer, requestID, requestLogID, originalInput)
}

func runFusionAdvisorRequest(
	ctx context.Context,
	br llm.Client,
	advisorReq *types.OpenAIChatRequest,
	config advisorConfig,
	advisorModel string,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
) (fusionCallResult, error) {
	return runAdvisorFusionOrchestrationRequest(ctx, br, advisorReq, config, advisorModel, trGateway, secretCache, bearer, requestID, requestLogID, originalInput)
}

func runAdvisorFusionWorkerRequest(
	ctx context.Context,
	br llm.Client,
	workerReq *types.OpenAIChatRequest,
	config advisorConfig,
	workerModel string,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
) (fusionCallResult, error) {
	return runAdvisorFusionOrchestrationRequest(ctx, br, workerReq, config, workerModel, trGateway, secretCache, bearer, requestID, requestLogID, originalInput)
}

func runAdvisorFusionOrchestrationRequest(
	ctx context.Context,
	br llm.Client,
	orchestrationReq *types.OpenAIChatRequest,
	config advisorConfig,
	orchestrationModel string,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	requestID string,
	requestLogID string,
	originalInput any,
) (fusionCallResult, error) {
	if config.Depth <= 0 {
		fmt.Fprintf(os.Stderr,
			"advisor.depth_blocked request_log_id=%q request_id=%q model=%q depth_remaining=%d\n",
			requestLogID, requestID, orchestrationModel, config.Depth,
		)
		return fusionCallResult{}, &adapter.AdapterError{Status: 400, Message: "trustedrouter orchestration depth exhausted", Context: "depth"}
	}
	childDepth := config.Depth - 1
	orchestrationReq.Depth = &childDepth
	fusionConfig, requested, err := fusionConfigForRequest(orchestrationReq)
	if err != nil {
		return fusionCallResult{}, err
	}
	if !requested {
		return fusionCallResult{}, &adapter.AdapterError{Status: 400, Message: "advisor model is not a supported orchestration model", Context: "advisor_model"}
	}
	if len(fusionConfig.AnalysisModels) == 0 {
		if preset, panel, ok := fusionPresetPanelForModel(orchestrationReq.Model); ok {
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
	finalModels, err := fusionFinalModels(fusionConfig, orchestrationReq.Model, fusionConfig.AnalysisModels[0])
	if err != nil {
		return fusionCallResult{}, err
	}
	judgeModels, err := fusionJudgeModels(fusionConfig, orchestrationReq.Model)
	if err != nil {
		return fusionCallResult{}, err
	}
	codeModel := isFusionCodeModel(orchestrationReq.Model)
	fusionConfig.CodeModel = codeModel
	if codeModel {
		fusionConfig.AnalysisModels = applyFusionCodeSwap(fusionConfig.AnalysisModels)
		judgeModels = applyFusionCodeSwap(judgeModels)
	}
	fusionConfig.BuiltInPanelPrompt, fusionConfig.BuiltInFinalPrompt = fusionBuiltInPrompts(codeModel)
	panel, err := runFusionPanel(ctx, br, orchestrationReq, fusionConfig, trGateway, secretCache, bearer, requestID+":fusion", requestLogID)
	if err != nil {
		return fusionCallResult{}, err
	}
	synthesisPanel, err := fusionPanelForSynthesis(panel, fusionConfig.SelectionStrategy)
	if err != nil {
		return fusionCallResult{}, err
	}
	judge, judgeAttempts, err := runFusionJudge(ctx, br, orchestrationReq, fusionConfig, judgeModels, synthesisPanel, trGateway, secretCache, bearer, requestID+":fusion", requestLogID)
	if err != nil {
		return fusionCallResult{}, err
	}
	final, finalAttempts, err := runFusionFinal(ctx, br, orchestrationReq, fusionConfig, finalModels, judge.Result.Text, synthesisPanel, trGateway, secretCache, bearer, requestID+":fusion", requestLogID, originalInput)
	if err != nil {
		return fusionCallResult{}, err
	}
	final.Orchestration = map[string]any{
		"synth": fusionResponseDetails(fusionConfig, panel, judgeAttempts, finalAttempts, requestOrchestrationResponseModel(orchestrationReq, orchestrationModel), final.Model),
	}
	totalIn, totalOut := fusionUsageTotals(panel, judgeAttempts, finalAttempts...)
	final.InputTokens = totalIn
	final.OutputTokens = totalOut
	final.Result.Usage = fusionAggregateStreamUsage(totalIn, totalOut, panel, judgeAttempts, finalAttempts)
	return final, nil
}

func advisorWorkerRequest(req *types.OpenAIChatRequest, model string, messages []types.OpenAIChatMessage, config advisorConfig, allowAdviceTool bool) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = model
	out.Models = nil
	forceFusionThroughputRouting(out)
	out.Stream = false
	out.Plugins = nil
	out.Messages = prependSystem(messages, config.BuiltInWorkerPrompt)
	out.Tools = stripTrustedRouterToolEntries(out.Tools)
	if allowAdviceTool {
		out.Tools = append(out.Tools, advisorAdviceTool())
	}
	if len(out.Tools) == 0 {
		out.ToolChoice = nil
	}
	out.Metadata = advisorMetadata(out.Metadata, "worker", model, config)
	return out
}

func advisorRequest(req *types.OpenAIChatRequest, model string, messages []types.OpenAIChatMessage, config advisorConfig) *types.OpenAIChatRequest {
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
	out.Metadata = advisorMetadata(out.Metadata, "advisor", model, config)
	return out
}

func advisorFinalRequest(req *types.OpenAIChatRequest, model string, messages []types.OpenAIChatMessage, config advisorConfig) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = model
	out.Models = nil
	forceFusionThroughputRouting(out)
	out.Stream = false
	out.Plugins = nil
	out.Tools = nil
	out.ToolChoice = nil
	out.MaxTokens = &config.AdvisorMaxTokens
	out.Messages = prependSystem(messages, fallbackAdvisorFinalPrompt)
	out.Metadata = advisorMetadata(out.Metadata, "advisor_final", model, config)
	return out
}

func advisorAdviceTool() map[string]any {
	return map[string]any{
		"type": "function",
		"function": map[string]any{
			"name":        advisorAdviceToolName,
			"description": "Ask a stronger TrustedRouter advisor for private guidance. For complex tasks, ask advice at major strategy checkpoints: before a costly/broad approach, after repeated stalls, or when choosing between plausible methods. Use routine commands yourself. Do not use for routine or straightforward work.",
			"parameters": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties":           map[string]any{},
			},
		},
	}
}

func rejectAdvisorToolCollision(tools []any, toolChoice any) error {
	for _, tool := range tools {
		m, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		if functionNameFromTool(m) == advisorAdviceToolName {
			return &adapter.AdapterError{Status: 400, Message: "_trustedrouter_get_advice is reserved for TrustedRouter advisor models", Context: "tools"}
		}
	}
	if toolChoiceFunctionName(toolChoice) == advisorAdviceToolName {
		return &adapter.AdapterError{Status: 400, Message: "_trustedrouter_get_advice is reserved for TrustedRouter advisor models", Context: "tool_choice"}
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
		if strings.HasPrefix(toolType, "trustedrouter:") || isSubagentToolType(toolType) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func advisorAdviceToolCall(calls []types.ToolCall) (types.ToolCall, bool) {
	for _, call := range calls {
		if strings.TrimSpace(call.Name) == advisorAdviceToolName {
			return call, true
		}
	}
	return types.ToolCall{}, false
}

func advisorAssistantToolMessage(call types.ToolCall) types.OpenAIChatMessage {
	return types.OpenAIChatMessage{
		Role:    "assistant",
		Content: nil,
		ToolCalls: []types.OpenAIToolCall{{
			ID:   advisorToolCallID(call, 0),
			Type: "function",
			Function: types.OpenAIToolFunction{
				Name:      advisorAdviceToolName,
				Arguments: "{}",
			},
		}},
	}
}

func advisorToolCallID(call types.ToolCall, index int) string {
	if call.ID != "" {
		return call.ID
	}
	if call.CallID != "" {
		return call.CallID
	}
	return fmt.Sprintf("call_advisor_advice_%d", index+1)
}

func advisorShouldAutoInitialAdvice(config advisorConfig) bool {
	return config.AutoInitialAdvice && config.MaxAdviceCalls > 0 && len(config.AdvisorModels) > 0
}

func advisorInitialAdviceMessage(adviceText string) string {
	return "Private TrustedRouter advisor guidance for this worker. Use it to improve the plan, but do not mention that advice was used unless directly relevant.\n\n" + strings.TrimSpace(adviceText)
}

func advisorMetadata(input map[string]any, stage string, model string, config advisorConfig) map[string]any {
	out := map[string]any{}
	for k, v := range input {
		out[k] = v
	}
	out["trustedrouter_router"] = trustedRouterAdvisorModel
	out["trustedrouter_advisor_stage"] = stage
	out["trustedrouter_advisor_model"] = model
	out["trustedrouter_orchestration_depth"] = config.Depth
	if config.AutoInitialAdvice {
		out["trustedrouter_advisor_auto_initial_advice"] = true
	}
	return out
}

func advisorResponseDetails(config advisorConfig, workerAttempts []fusionCallResult, advisorAttempts []fusionCallResult, routerModel string, selectedModel string, adviceCalls int, budgetExhausted bool) map[string]any {
	details := map[string]any{
		"router":                  routerModel,
		"primitive":               trustedRouterAdvisorModel,
		"version":                 "1.0",
		"selected_model":          selectedModel,
		"depth_initial":           config.Depth,
		"max_get_advice_calls":    config.MaxAdviceCalls,
		"worker_timeout_ms":       config.WorkerTimeoutMS,
		"auto_initial_advice":     config.AutoInitialAdvice,
		"advice_call_count":       adviceCalls,
		"advice_budget_exhausted": budgetExhausted,
		"worker_attempts":         advisorSafeCallDetailsList(workerAttempts, true),
		"advisor_attempts":        advisorSafeCallDetailsList(advisorAttempts, false),
	}
	if cost := advisorTotalCostMicrodollars(workerAttempts, advisorAttempts); cost > 0 {
		details["cost_microdollars"] = cost
	}
	if config.HidePublicMetadata {
		details["_hide_public_metadata"] = true
	}
	return details
}

func advisorSafeCallDetailsList(items []fusionCallResult, includeText bool) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, advisorSafeCallDetails(item, includeText))
	}
	return out
}

func advisorSafeCallDetails(item fusionCallResult, includeText bool) map[string]any {
	detail := fusionCallDetails(item)
	if routeType, ok := detail["route_type"]; ok {
		detail["route_type"] = publicOrchestrationRouteType(routeType, trustedRouterAdvisorModel)
	}
	if !includeText {
		delete(detail, "visible_answer")
		delete(detail, "raw_output")
		delete(detail, "thinking")
		delete(detail, "tool_calls")
	}
	return detail
}

func advisorUsageTotals(groups ...[]fusionCallResult) (int, int) {
	var inputs int
	var outputs int
	for _, items := range groups {
		for _, item := range items {
			inputs += fusionCallPromptTokens(item)
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

func advisorTotalCostMicrodollars(groups ...[]fusionCallResult) int {
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

func advisorPublicStreamUsage(config advisorConfig, inputTokens int, outputTokens int, groups ...[]fusionCallResult) *adapter.StreamUsage {
	return fusionAggregateStreamUsage(inputTokens, outputTokens, groups...)
}

func advisorHidePublicMetadata(details map[string]any) bool {
	hidden, _ := details["_hide_public_metadata"].(bool)
	return hidden
}

func writeAdvisorChatCompletionResponse(
	w io.Writer,
	requestID string,
	model string,
	text string,
	reasoning string,
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
		reasoning,
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
	hidePublicMetadata := advisorHidePublicMetadata(details)
	if !hidePublicMetadata {
		payload["trustedrouter"] = map[string]any{orchestrationDetailKey(details, trustedRouterAdvisorModel): details}
	}
	if usage, ok := payload["usage"].(map[string]any); ok {
		if cost, ok := fusionCostMicrodollars(details); ok {
			usage["cost_microdollars"] = cost
		}
		if providerUsage := advisorPublicProviderUsage(details); len(providerUsage) > 0 {
			usage["provider_usage"] = providerUsage
			applyUsageProviderSummary(usage, providerUsage)
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = w.Write(encoded)
	return err
}

func writeAdvisorStreamEvent(w io.Writer, requestID string, model string, created int64, event map[string]any) error {
	chunk := map[string]any{
		"id":            requestID,
		"object":        "chat.completion.chunk",
		"created":       created,
		"model":         model,
		"choices":       []map[string]any{},
		"trustedrouter": map[string]any{"advisor": event},
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

func writeHiddenAdvisorStreamError(w io.Writer, requestID string, model string, created int64) error {
	chunk := map[string]any{
		"id":      requestID,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []map[string]any{{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": "stop",
		}},
		"error": map[string]any{
			"message": "model request failed",
			"type":    "upstream_error",
		},
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
	_, err = w.Write([]byte("\n\ndata: [DONE]\n\n"))
	return err
}

func writeHiddenAdvisorStreamUsage(w io.Writer, requestID string, model string, created int64, result fusionCallResult, totalCostMicrodollars int, providerUsage map[string]any) error {
	usage := map[string]any{
		"prompt_tokens":     result.InputTokens,
		"completion_tokens": result.OutputTokens,
		"total_tokens":      result.InputTokens + result.OutputTokens,
	}
	if totalCostMicrodollars > 0 {
		usage["cost_microdollars"] = totalCostMicrodollars
	}
	if len(providerUsage) > 0 {
		usage["provider_usage"] = providerUsage
		applyUsageProviderSummary(usage, providerUsage)
	}
	if result.Result.Usage != nil && result.Result.Usage.ReasoningTokens > 0 {
		usage["completion_tokens_details"] = map[string]any{
			"reasoning_tokens": result.Result.Usage.ReasoningTokens,
		}
	}
	if result.Result.Usage != nil && result.Result.Usage.CacheReadInputTokens > 0 {
		usage["prompt_tokens_details"] = map[string]any{
			"cached_tokens": result.Result.Usage.CacheReadInputTokens,
		}
	}
	chunk := map[string]any{
		"id":      requestID,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []map[string]any{},
		"usage":   usage,
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

func writeAdvisorStreamError(w io.Writer, requestID string, model string, created int64, err error, workerAttempts []fusionCallResult, advisorAttempts []fusionCallResult) error {
	if err == nil {
		return nil
	}
	if writeErr := writeAdvisorStreamEvent(w, requestID, model, created, advisorStreamErrorEvent(err, workerAttempts, advisorAttempts)); writeErr != nil {
		return writeErr
	}
	_, writeErr := w.Write([]byte("data: [DONE]\n\n"))
	return writeErr
}

func advisorStreamErrorEvent(err error, workerAttempts []fusionCallResult, advisorAttempts []fusionCallResult) map[string]any {
	event := map[string]any{
		"event": "advisor.error",
		"error": err.Error(),
	}
	var callErr *orchestrationCallError
	if errors.As(err, &callErr) && callErr != nil {
		event["stage"] = callErr.Stage
		event["model"] = callErr.AttemptedModel
		event["attempted_model"] = callErr.AttemptedModel
		event["endpoint"] = callErr.Endpoint
		event["provider"] = callErr.Provider
		event["input_tokens"] = callErr.InputTokens
		event["output_tokens"] = callErr.OutputTokens
		if callErr.UsageEstimated {
			event["usage_estimated"] = true
		}
		event["provider_error_class"] = callErr.ProviderErrorClass
		event["provider_error_detail"] = callErr.ProviderErrorDetail
		event["detail"] = map[string]any{
			"model":                 callErr.AttemptedModel,
			"endpoint":              callErr.Endpoint,
			"provider":              callErr.Provider,
			"input_tokens":          callErr.InputTokens,
			"output_tokens":         callErr.OutputTokens,
			"usage_estimated":       callErr.UsageEstimated,
			"provider_error_class":  callErr.ProviderErrorClass,
			"provider_error_detail": callErr.ProviderErrorDetail,
		}
		return event
	}
	if detail, stage, ok := advisorLastAttemptDetail(workerAttempts, advisorAttempts); ok {
		event["stage"] = stage
		if model, _ := detail["model"].(string); model != "" {
			event["model"] = model
			event["attempted_model"] = model
		}
		if endpoint, _ := detail["endpoint"].(string); endpoint != "" {
			event["endpoint"] = endpoint
		}
		if inputTokens, ok := detail["input_tokens"]; ok {
			event["input_tokens"] = inputTokens
		}
		if outputTokens, ok := detail["output_tokens"]; ok {
			event["output_tokens"] = outputTokens
		}
		event["provider_error_class"] = errorClass(err)
		event["provider_error_detail"] = err.Error()
		detail["provider_error_class"] = errorClass(err)
		detail["provider_error_detail"] = err.Error()
		event["detail"] = detail
		return event
	}
	event["provider_error_class"] = errorClass(err)
	event["provider_error_detail"] = err.Error()
	return event
}

func advisorLastAttemptDetail(workerAttempts []fusionCallResult, advisorAttempts []fusionCallResult) (map[string]any, string, bool) {
	if len(advisorAttempts) > 0 {
		return advisorSafeCallDetails(advisorAttempts[len(advisorAttempts)-1], false), "advisor_final", true
	}
	if len(workerAttempts) > 0 {
		return advisorSafeCallDetails(workerAttempts[len(workerAttempts)-1], false), "worker", true
	}
	return nil, "", false
}
