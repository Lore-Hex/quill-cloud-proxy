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
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const trustedRouterSubagentModel = "trustedrouter/subagent"
const trustedRouterSubagentTool = "trustedrouter:subagent"
const openRouterSubagentTool = "openrouter:subagent"
const subagentPrivateToolName = "_trustedrouter_subagent"

const defaultSubagentMaxCalls = 4
const maxSubagentMaxCalls = 25
const defaultSubagentMaxCompletionTokens = 1024
const maxSubagentMaxCompletionTokens = 8192

type subagentConfig struct {
	Enabled             bool
	Depth               int
	DepthSet            bool
	ControllerModel     string
	WorkerModel         string
	Instructions        string
	MaxCalls            int
	MaxCallsSet         bool
	MaxCompletionTokens int
	Temperature         *float64
	Reasoning           any
	WorkerTools         []any
}

func isSubagentModel(model string) bool {
	return strings.EqualFold(strings.TrimSpace(model), trustedRouterSubagentModel)
}

func isSubagentToolType(toolType string) bool {
	switch strings.ToLower(strings.TrimSpace(toolType)) {
	case trustedRouterSubagentTool, openRouterSubagentTool:
		return true
	default:
		return false
	}
}

func maybeServeSubagent(
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
	config, requested, err := subagentConfigForRequest(req)
	if err != nil {
		return true, err
	}
	if !requested {
		return false, nil
	}
	if !config.Enabled {
		if isSubagentModel(req.Model) {
			return true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent cannot be disabled without selecting a concrete model", Context: "trustedrouter:subagent.enabled"}
		}
		return false, nil
	}
	if trGateway == nil || !trGateway.Enabled() {
		return true, &adapter.AdapterError{Status: 503, Message: "trustedrouter/subagent requires the TrustedRouter control plane", Context: "trustedrouter/subagent"}
	}
	if err := normalizeSubagentConfig(&config, req); err != nil {
		return true, err
	}
	if err := rejectSubagentToolCollision(req.Tools, req.ToolChoice); err != nil {
		return true, err
	}

	fmt.Fprintf(os.Stderr,
		"subagent.request_start request_log_id=%q model=%q controller_model=%q worker_model=%q depth_initial=%d max_subagent_calls=%d\n",
		requestLogID, req.Model, config.ControllerModel, config.WorkerModel, config.Depth, config.MaxCalls,
	)
	if req.Stream {
		serveSubagentStreaming(ctx, conn, br, req, config, trGateway, secretCache, bearer, originalInput, requestLogID)
	} else {
		serveSubagentNonStreaming(ctx, conn, br, req, config, trGateway, secretCache, bearer, originalInput, requestLogID)
	}
	return true, nil
}

func subagentConfigForRequest(req *types.OpenAIChatRequest) (subagentConfig, bool, error) {
	config := subagentConfig{Enabled: true}
	requested := isSubagentModel(req.Model)
	if req.Depth != nil {
		config.Depth = *req.Depth
		config.DepthSet = true
	}
	cleanTools, toolConfig, toolRequested, err := subagentConfigFromTools(req.Tools)
	if err != nil {
		return subagentConfig{}, true, err
	}
	if toolRequested {
		config = mergeSubagentConfig(config, toolConfig)
		requested = true
		req.Tools = cleanTools
	}
	return config, requested, nil
}

func subagentConfigFromTools(tools []any) ([]any, subagentConfig, bool, error) {
	if len(tools) == 0 {
		return tools, subagentConfig{}, false, nil
	}
	clean := make([]any, 0, len(tools))
	config := subagentConfig{Enabled: true}
	var requested bool
	for _, item := range tools {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, subagentConfig{}, false, &adapter.AdapterError{Status: 400, Message: "tool must be an object", Context: "tools"}
		}
		toolType := strings.TrimSpace(stringValue(m["type"]))
		if !isSubagentToolType(toolType) {
			clean = append(clean, item)
			continue
		}
		params, err := fusionParametersMap(m["parameters"], "tools.parameters")
		if err != nil {
			return nil, subagentConfig{}, true, err
		}
		parsed, err := parseSubagentParameters(params)
		if err != nil {
			return nil, subagentConfig{}, true, err
		}
		config = mergeSubagentConfig(config, parsed)
		requested = true
	}
	return clean, config, requested, nil
}

func parseSubagentParameters(raw map[string]any) (subagentConfig, error) {
	config := subagentConfig{Enabled: true}
	if raw == nil {
		return config, nil
	}
	if enabled, ok := raw["enabled"]; ok {
		value, ok := enabled.(bool)
		if !ok {
			return config, &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent enabled must be boolean", Context: "enabled"}
		}
		config.Enabled = value
	}
	if model := strings.TrimSpace(stringValue(raw["model"])); model != "" {
		config.WorkerModel = model
	}
	if model := strings.TrimSpace(stringValue(raw["controller_model"])); model != "" {
		config.ControllerModel = model
	}
	if instructions, ok, err := optionalStringField(raw, "instructions", 16_384); err != nil {
		return config, err
	} else if ok {
		config.Instructions = instructions
	}
	if n, ok, err := intField(raw, "depth"); err != nil {
		return config, err
	} else if ok {
		config.Depth = n
		config.DepthSet = true
	}
	for _, name := range []string{"max_subagent_calls", "max_tool_calls"} {
		if n, ok, err := intField(raw, name); err != nil {
			return config, err
		} else if ok {
			config.MaxCalls = n
			config.MaxCallsSet = true
			break
		}
	}
	for _, name := range []string{"max_completion_tokens", "max_tokens"} {
		if n, ok, err := intField(raw, name); err != nil {
			return config, err
		} else if ok {
			config.MaxCompletionTokens = n
			break
		}
	}
	if temperature, ok, err := optionalFloatField(raw, "temperature"); err != nil {
		return config, err
	} else if ok {
		config.Temperature = &temperature
	}
	if reasoning, ok := raw["reasoning"]; ok {
		config.Reasoning = reasoning
	}
	if workerTools, ok := raw["tools"]; ok {
		items, ok := workerTools.([]any)
		if !ok {
			return config, &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent tools must be an array", Context: "tools"}
		}
		config.WorkerTools = append([]any(nil), items...)
	}
	return config, nil
}

func mergeSubagentConfig(base, override subagentConfig) subagentConfig {
	if !override.Enabled {
		base.Enabled = false
	}
	if override.DepthSet {
		base.Depth = override.Depth
		base.DepthSet = true
	}
	if override.ControllerModel != "" {
		base.ControllerModel = override.ControllerModel
	}
	if override.WorkerModel != "" {
		base.WorkerModel = override.WorkerModel
	}
	if override.Instructions != "" {
		base.Instructions = override.Instructions
	}
	if override.MaxCallsSet {
		base.MaxCalls = override.MaxCalls
		base.MaxCallsSet = true
	}
	if override.MaxCompletionTokens != 0 {
		base.MaxCompletionTokens = override.MaxCompletionTokens
	}
	if override.Temperature != nil {
		base.Temperature = override.Temperature
	}
	if override.Reasoning != nil {
		base.Reasoning = override.Reasoning
	}
	if len(override.WorkerTools) > 0 {
		base.WorkerTools = append([]any(nil), override.WorkerTools...)
	}
	return base
}

func normalizeSubagentConfig(config *subagentConfig, req *types.OpenAIChatRequest) error {
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
	if !config.MaxCallsSet {
		config.MaxCalls = defaultSubagentMaxCalls
	}
	if config.MaxCalls < 1 || config.MaxCalls > maxSubagentMaxCalls {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent max_tool_calls must be between 1 and 25", Context: "max_tool_calls"}
	}
	if config.MaxCompletionTokens == 0 {
		config.MaxCompletionTokens = defaultSubagentMaxCompletionTokens
	}
	if config.MaxCompletionTokens < 1 || config.MaxCompletionTokens > maxSubagentMaxCompletionTokens {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent max_completion_tokens must be between 1 and 8192", Context: "max_completion_tokens"}
	}
	if config.Temperature != nil && (*config.Temperature < 0 || *config.Temperature > 2) {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent temperature must be between 0 and 2", Context: "temperature"}
	}
	if config.ControllerModel == "" {
		if isSubagentModel(req.Model) {
			return &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent requires controller_model when used as the request model; use a concrete outer model with an openrouter:subagent tool for OpenRouter-compatible calls", Context: "controller_model"}
		}
		config.ControllerModel = req.Model
	}
	config.ControllerModel = resolveFusionModelID(config.ControllerModel)
	if config.ControllerModel == "" || isSubagentModel(config.ControllerModel) {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent controller_model must be a concrete model id, not trustedrouter/subagent", Context: "controller_model"}
	}
	if isAdvisorOrchestrationModel(config.ControllerModel) || isFusionModel(config.ControllerModel) {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent controller_model must be a concrete model id in alpha", Context: "controller_model"}
	}
	if config.WorkerModel == "" {
		config.WorkerModel = config.ControllerModel
	}
	config.WorkerModel = resolveFusionModelID(config.WorkerModel)
	if config.WorkerModel == "" || isSubagentModel(config.WorkerModel) {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent model must be a concrete model id, not trustedrouter/subagent", Context: "model"}
	}
	if isAdvisorOrchestrationModel(config.WorkerModel) || isFusionModel(config.WorkerModel) {
		return &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent model must be a concrete model id in alpha", Context: "model"}
	}
	if err := validateSubagentWorkerTools(config.WorkerTools); err != nil {
		return err
	}
	return nil
}

func validateSubagentWorkerTools(tools []any) error {
	if len(tools) == 0 {
		return nil
	}
	for _, tool := range tools {
		m, ok := tool.(map[string]any)
		if !ok {
			return &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent worker tools must be objects", Context: "tools"}
		}
		toolType := strings.ToLower(strings.TrimSpace(stringValue(m["type"])))
		if toolType == "function" {
			return &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent worker tools only support server tools, not function tools", Context: "tools"}
		}
		if isSubagentToolType(toolType) {
			return &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent worker tools cannot include subagent recursively", Context: "tools"}
		}
	}
	return &adapter.AdapterError{Status: 501, Message: "trustedrouter/subagent worker server tools are not supported in alpha", Context: "tools"}
}

func serveSubagentNonStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config subagentConfig,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestLogID string,
) {
	started := time.Now()
	requestID := newRequestID()
	final, controllers, workers, callCount, budgetExhausted, err := runSubagent(ctx, br, req, config, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, nil, 0, nil)
	if err != nil {
		writeFusionError(ctx, conn, trGateway, err)
		return
	}
	totalIn, totalOut := advisorUsageTotals(controllers, workers)
	selectedModel := final.Model
	if selectedModel == "" {
		selectedModel = config.ControllerModel
	}
	responseModel := requestOrchestrationResponseModel(req, selectedModel)
	details := subagentResponseDetails(config, controllers, workers, responseModel, selectedModel, callCount, budgetExhausted)
	var body bytes.Buffer
	if err := writeSubagentChatCompletionResponse(&body, requestID, responseModel, final.Result.Text, final.Result.ToolCalls, totalIn, totalOut, fusionAggregateStreamUsage(totalIn, totalOut, controllers, workers), time.Now().Unix(), final.Result.FinishReason, details); err != nil {
		writeError(conn, 500, "subagent response encoding error")
		return
	}
	fmt.Fprintf(os.Stderr,
		"subagent.request_end request_log_id=%q request_id=%q mode=nonstream outcome=%q subagent_call_count=%d selected_model=%q elapsed_ms=%d\n",
		requestLogID, requestID, "success", callCount, responseModel, time.Since(started).Milliseconds(),
	)
	writeJSONResponse(conn, 200, body.Bytes())
}

func serveSubagentStreaming(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config subagentConfig,
	trGateway *trustedrouter.Client,
	secretCache *byokcache.Cache,
	bearer string,
	originalInput any,
	requestLogID string,
) {
	started := time.Now()
	requestID := newRequestID()
	created := time.Now().Unix()
	if err := writeResponseHead(conn, 200, "text/event-stream"); err != nil {
		return
	}
	chunkW := newChunkedWriter(conn)
	defer chunkW.Close()
	statsW := newStreamStatsWriter(chunkW)
	emitter := newSubagentStreamEmitter(statsW, requestID, req.Model, created)
	emitter.Event(map[string]any{
		"event":              "subagent.started",
		"depth_initial":      config.Depth,
		"max_subagent_calls": config.MaxCalls,
		"controller_model":   config.ControllerModel,
		"worker_model":       config.WorkerModel,
	})
	final, controllers, workers, callCount, budgetExhausted, err := runSubagent(ctx, br, req, config, trGateway, secretCache, bearer, requestID, requestLogID, originalInput, statsW, created, emitter.Observer)
	if err != nil {
		_ = writeSubagentStreamError(statsW, requestID, req.Model, created, err, controllers, workers)
		return
	}
	selectedModel := final.Model
	if selectedModel == "" {
		selectedModel = config.ControllerModel
	}
	responseModel := requestOrchestrationResponseModel(req, selectedModel)
	if len(final.Result.ToolCalls) > 0 {
		_ = writeSubagentStreamEvent(statsW, requestID, responseModel, created, map[string]any{
			"event":      "subagent.tool_calls",
			"tool_calls": final.Result.ToolCalls,
		})
	} else if text := strings.TrimSpace(final.Result.Text); text != "" {
		_ = writeFusionStreamDelta(statsW, requestID, responseModel, created, map[string]any{"content": text}, "")
	}
	if err := writeFusionStreamDelta(statsW, requestID, responseModel, created, map[string]any{}, final.Result.FinishReason); err != nil {
		return
	}
	if chatIncludeUsage(req) {
		totalIn, totalOut := advisorUsageTotals(controllers, workers)
		usage := final
		usage.InputTokens = totalIn
		usage.OutputTokens = totalOut
		usage.Result.Usage = fusionAggregateStreamUsage(totalIn, totalOut, controllers, workers)
		details := subagentResponseDetails(config, controllers, workers, responseModel, selectedModel, callCount, budgetExhausted)
		_ = writeFusionStreamUsage(statsW, requestID, responseModel, created, usage, advisorTotalCostMicrodollars(controllers, workers), subagentProviderUsage(details))
	}
	_, _ = statsW.Write([]byte("data: [DONE]\n\n"))
	fmt.Fprintf(os.Stderr,
		"subagent.request_end request_log_id=%q request_id=%q mode=stream outcome=%q subagent_call_count=%d selected_model=%q elapsed_ms=%d\n",
		requestLogID, requestID, "success", callCount, responseModel, time.Since(started).Milliseconds(),
	)
}

func runSubagent(
	ctx context.Context,
	br llm.Client,
	req *types.OpenAIChatRequest,
	config subagentConfig,
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
	controllerAttempts := make([]fusionCallResult, 0, config.MaxCalls+2)
	workerAttempts := make([]fusionCallResult, 0, config.MaxCalls)
	subagentCalls := 0
	budgetExhausted := false
	allowSubagentTool := true
	for turn := 0; turn < config.MaxCalls+3; turn++ {
		if streamW != nil {
			_ = writeSubagentStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event": "controller.started",
				"stage": "controller",
				"index": turn,
				"model": config.ControllerModel,
			})
		}
		controllerReq := subagentControllerRequest(req, config, messages, allowSubagentTool)
		var observer adapter.StreamObserver
		if observerFactory != nil {
			observer = observerFactory("controller", turn, config.ControllerModel)
		}
		controller, err := runFusionCallObserved(ctx, br, controllerReq, trGateway, secretCache, bearer, "subagent.controller", fmt.Sprintf("%s:controller:%d", requestID, turn), requestLogID, originalInput, false, observer, streamW != nil)
		if err != nil {
			return fusionCallResult{}, controllerAttempts, workerAttempts, subagentCalls, budgetExhausted, err
		}
		controller.RouteType = "subagent.controller"
		controllerAttempts = append(controllerAttempts, controller)
		if streamW != nil {
			_ = writeSubagentStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event":  "controller.done",
				"stage":  "controller",
				"index":  turn,
				"model":  config.ControllerModel,
				"detail": subagentSafeCallDetails(controller),
			})
		}
		call, hasSubagent := subagentToolCall(controller.Result.ToolCalls)
		if !hasSubagent {
			if strings.TrimSpace(controller.Result.Text) == "" && len(controller.Result.ToolCalls) == 0 {
				return fusionCallResult{}, controllerAttempts, workerAttempts, subagentCalls, budgetExhausted, &adapter.AdapterError{Status: 502, Message: "trustedrouter/subagent controller returned an empty response", Context: "subagent.controller"}
			}
			return controller, controllerAttempts, workerAttempts, subagentCalls, budgetExhausted, nil
		}
		if subagentCalls >= config.MaxCalls {
			budgetExhausted = true
			messages = append(messages, subagentAssistantToolMessage(call), types.OpenAIChatMessage{
				Role:       "tool",
				Name:       subagentPrivateToolName,
				ToolCallID: subagentToolCallID(call, turn),
				Content:    subagentToolResultJSON("error", "", "Subagent call budget exhausted. Answer now."),
			})
			allowSubagentTool = false
			continue
		}
		subagentCalls++
		task, err := parseSubagentTask(call)
		if err != nil {
			messages = append(messages, subagentAssistantToolMessage(call), types.OpenAIChatMessage{
				Role:       "tool",
				Name:       subagentPrivateToolName,
				ToolCallID: subagentToolCallID(call, turn),
				Content:    subagentToolResultJSON("error", "", err.Error()),
			})
			continue
		}
		if streamW != nil {
			_ = writeSubagentStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event":     "subagent_call.started",
				"stage":     "subagent",
				"index":     subagentCalls - 1,
				"model":     config.WorkerModel,
				"task_name": task.Name,
			})
		}
		workerReq := subagentWorkerRequest(req, config, task)
		var workerObserver adapter.StreamObserver
		if observerFactory != nil {
			workerObserver = observerFactory("subagent", subagentCalls-1, config.WorkerModel)
		}
		worker, err := runFusionCallObserved(ctx, br, workerReq, trGateway, secretCache, bearer, "subagent.worker", fmt.Sprintf("%s:subagent:%d", requestID, subagentCalls), requestLogID, originalInput, false, workerObserver, streamW != nil)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"subagent.worker_failed request_log_id=%q request_id=%q worker_model=%q call_index=%d error=%q\n",
				requestLogID, requestID, config.WorkerModel, subagentCalls, err.Error(),
			)
			messages = append(messages, subagentAssistantToolMessage(call), types.OpenAIChatMessage{
				Role:       "tool",
				Name:       subagentPrivateToolName,
				ToolCallID: subagentToolCallID(call, turn),
				Content:    subagentToolResultJSON("error", task.Name, "Subagent call failed: "+err.Error()),
			})
			continue
		}
		worker.RouteType = "subagent.worker"
		workerAttempts = append(workerAttempts, worker)
		if streamW != nil {
			_ = writeSubagentStreamEvent(streamW, requestID, req.Model, streamCreated, map[string]any{
				"event":     "subagent_call.done",
				"stage":     "subagent",
				"index":     subagentCalls - 1,
				"model":     config.WorkerModel,
				"task_name": task.Name,
				"detail":    subagentSafeCallDetails(worker),
			})
		}
		outcome := strings.TrimSpace(worker.Result.Text)
		if outcome == "" {
			outcome = adapter.ResponsesOutputForUsage(worker.Result)
		}
		messages = append(messages, subagentAssistantToolMessage(call), types.OpenAIChatMessage{
			Role:       "tool",
			Name:       subagentPrivateToolName,
			ToolCallID: subagentToolCallID(call, turn),
			Content:    subagentToolResultJSON("ok", task.Name, outcome),
		})
	}
	return fusionCallResult{}, controllerAttempts, workerAttempts, subagentCalls, budgetExhausted, &adapter.AdapterError{Status: 502, Message: "trustedrouter/subagent did not complete", Context: "subagent"}
}

type subagentTask struct {
	Name        string
	Description string
}

func parseSubagentTask(call types.ToolCall) (subagentTask, error) {
	var raw struct {
		TaskName        string `json:"task_name"`
		TaskDescription string `json:"task_description"`
	}
	if err := json.Unmarshal([]byte(call.Arguments), &raw); err != nil {
		return subagentTask{}, fmt.Errorf("Invalid subagent arguments: %w", err)
	}
	task := subagentTask{
		Name:        strings.TrimSpace(raw.TaskName),
		Description: strings.TrimSpace(raw.TaskDescription),
	}
	if task.Name == "" {
		task.Name = "subtask"
	}
	if task.Description == "" {
		return subagentTask{}, fmt.Errorf("task_description is required")
	}
	return task, nil
}

func subagentControllerRequest(req *types.OpenAIChatRequest, config subagentConfig, messages []types.OpenAIChatMessage, allowSubagentTool bool) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = config.ControllerModel
	out.Models = nil
	forceFusionThroughputRouting(out)
	out.Stream = false
	out.Plugins = nil
	out.Messages = messages
	out.Tools = stripSubagentToolEntries(out.Tools)
	if allowSubagentTool {
		out.Tools = append(out.Tools, subagentPrivateTool(config))
	}
	if len(out.Tools) == 0 {
		out.ToolChoice = nil
	}
	out.Metadata = subagentMetadata(out.Metadata, "controller", config.ControllerModel, config)
	return out
}

func subagentWorkerRequest(req *types.OpenAIChatRequest, config subagentConfig, task subagentTask) *types.OpenAIChatRequest {
	out := cloneChatRequest(req)
	out.Model = config.WorkerModel
	out.Models = nil
	forceFusionThroughputRouting(out)
	out.Stream = false
	out.Plugins = nil
	out.Tools = nil
	out.ToolChoice = nil
	out.ResponseFormat = nil
	out.MaxTokens = &config.MaxCompletionTokens
	out.Temperature = config.Temperature
	out.Reasoning = config.Reasoning
	out.Messages = []types.OpenAIChatMessage{{Role: "user", Content: task.Description}}
	if strings.TrimSpace(config.Instructions) != "" {
		out.Messages = prependSystem(out.Messages, config.Instructions)
	}
	out.Metadata = subagentMetadata(out.Metadata, "worker", config.WorkerModel, config)
	return out
}

func subagentPrivateTool(config subagentConfig) map[string]any {
	description := "Delegate a self-contained task to a TrustedRouter subagent worker. Use this only when a separate worker can answer a bounded subtask better or faster than continuing inline."
	if config.WorkerModel != "" {
		description += " Worker model: " + config.WorkerModel + "."
	}
	return map[string]any{
		"type": "function",
		"function": map[string]any{
			"name":        subagentPrivateToolName,
			"description": description,
			"parameters": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"task_name": map[string]any{
						"type":        "string",
						"description": "Short machine-readable name for the delegated task.",
					},
					"task_description": map[string]any{
						"type":        "string",
						"description": "Self-contained instructions for the subagent. Include all context the worker needs.",
					},
				},
				"required": []string{"task_name", "task_description"},
			},
		},
	}
}

func subagentToolCall(calls []types.ToolCall) (types.ToolCall, bool) {
	for _, call := range calls {
		if strings.TrimSpace(call.Name) == subagentPrivateToolName {
			return call, true
		}
	}
	return types.ToolCall{}, false
}

func subagentAssistantToolMessage(call types.ToolCall) types.OpenAIChatMessage {
	id := call.ID
	if id == "" {
		id = call.CallID
	}
	if id == "" {
		id = "call_subagent"
	}
	return types.OpenAIChatMessage{
		Role:    "assistant",
		Content: nil,
		ToolCalls: []types.OpenAIToolCall{{
			ID:   id,
			Type: "function",
			Function: types.OpenAIToolFunction{
				Name:      subagentPrivateToolName,
				Arguments: call.Arguments,
			},
		}},
	}
}

func subagentToolCallID(call types.ToolCall, fallback int) string {
	if call.ID != "" {
		return call.ID
	}
	if call.CallID != "" {
		return call.CallID
	}
	return fmt.Sprintf("call_subagent_%d", fallback+1)
}

func subagentToolResultJSON(status string, taskName string, value string) string {
	payload := map[string]any{
		"status": status,
	}
	if taskName != "" {
		payload["task_name"] = taskName
	}
	if status == "ok" {
		payload["outcome"] = value
	} else {
		payload["error"] = value
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return `{"status":"error","error":"Subagent result encoding failed"}`
	}
	return string(encoded)
}

func rejectSubagentToolCollision(tools []any, toolChoice any) error {
	for _, tool := range tools {
		m, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		if functionNameFromTool(m) == subagentPrivateToolName {
			return &adapter.AdapterError{Status: 400, Message: "_trustedrouter_subagent is reserved for TrustedRouter subagent calls", Context: "tools"}
		}
	}
	if toolChoiceFunctionName(toolChoice) == subagentPrivateToolName {
		return &adapter.AdapterError{Status: 400, Message: "_trustedrouter_subagent is reserved for TrustedRouter subagent calls", Context: "tool_choice"}
	}
	return nil
}

func stripSubagentToolEntries(tools []any) []any {
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
		if isSubagentToolType(stringValue(m["type"])) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func subagentMetadata(metadata map[string]any, stage string, model string, config subagentConfig) map[string]any {
	out := map[string]any{}
	for k, v := range metadata {
		out[k] = v
	}
	out["trustedrouter_router"] = trustedRouterSubagentModel
	out["trustedrouter_subagent_stage"] = stage
	out["trustedrouter_subagent_model"] = model
	out["trustedrouter_orchestration_depth"] = config.Depth
	return out
}

func subagentSafeCallDetails(item fusionCallResult) map[string]any {
	detail := fusionCallDetails(item)
	if routeType, ok := detail["route_type"]; ok {
		detail["route_type"] = publicOrchestrationRouteType(routeType, trustedRouterSubagentModel)
	}
	for _, key := range []string{"visible_answer", "raw_output", "thinking", "tool_calls", "aborted_thinking"} {
		delete(detail, key)
	}
	return detail
}

func subagentResponseDetails(config subagentConfig, controllerAttempts []fusionCallResult, workerAttempts []fusionCallResult, routerModel string, selectedModel string, callCount int, budgetExhausted bool) map[string]any {
	details := map[string]any{
		"router":                    routerModel,
		"primitive":                 trustedRouterSubagentModel,
		"version":                   "1.0",
		"selected_model":            selectedModel,
		"controller_model":          config.ControllerModel,
		"worker_model":              config.WorkerModel,
		"depth_initial":             config.Depth,
		"max_subagent_calls":        config.MaxCalls,
		"subagent_call_count":       callCount,
		"subagent_budget_exhausted": budgetExhausted,
		"controller_attempts":       subagentCallDetailsList(controllerAttempts),
		"subagent_attempts":         subagentCallDetailsList(workerAttempts),
	}
	if cost := advisorTotalCostMicrodollars(controllerAttempts, workerAttempts); cost > 0 {
		details["cost_microdollars"] = cost
	}
	return details
}

func subagentCallDetailsList(items []fusionCallResult) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, subagentSafeCallDetails(item))
	}
	return out
}

func writeSubagentChatCompletionResponse(
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
	if err := adapter.WriteChatCompletionResponse(&body, requestID, model, text, toolCalls, inputTokens, outputTokens, usage, created, finishReason); err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(body.Bytes(), &payload); err != nil {
		return err
	}
	payload["trustedrouter"] = map[string]any{"subagent": details}
	if usage, ok := payload["usage"].(map[string]any); ok {
		if cost, ok := fusionCostMicrodollars(details); ok {
			usage["cost_microdollars"] = cost
		}
		if providerUsage := subagentProviderUsage(details); len(providerUsage) > 0 {
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

func writeSubagentStreamEvent(w io.Writer, requestID string, model string, created int64, event map[string]any) error {
	chunk := map[string]any{
		"id":            requestID,
		"object":        "chat.completion.chunk",
		"created":       created,
		"model":         model,
		"choices":       []map[string]any{},
		"trustedrouter": map[string]any{"subagent": event},
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

func writeSubagentStreamError(w io.Writer, requestID string, model string, created int64, err error, controllerAttempts []fusionCallResult, workerAttempts []fusionCallResult) error {
	if err == nil {
		return nil
	}
	event := map[string]any{
		"event": "subagent.error",
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
		event["provider_error_class"] = callErr.ProviderErrorClass
		event["provider_error_detail"] = callErr.ProviderErrorDetail
	}
	if len(controllerAttempts) > 0 {
		event["controller_attempts"] = subagentCallDetailsList(controllerAttempts)
	}
	if len(workerAttempts) > 0 {
		event["subagent_attempts"] = subagentCallDetailsList(workerAttempts)
	}
	if writeErr := writeSubagentStreamEvent(w, requestID, model, created, event); writeErr != nil {
		return writeErr
	}
	_, writeErr := w.Write([]byte("data: [DONE]\n\n"))
	return writeErr
}

type subagentStreamEmitter struct {
	w         io.Writer
	requestID string
	model     string
	created   int64
}

func newSubagentStreamEmitter(w io.Writer, requestID string, model string, created int64) *subagentStreamEmitter {
	return &subagentStreamEmitter{w: w, requestID: requestID, model: model, created: created}
}

func (e *subagentStreamEmitter) Event(event map[string]any) {
	if e == nil || e.w == nil {
		return
	}
	_ = writeSubagentStreamEvent(e.w, e.requestID, e.model, e.created, event)
}

func (e *subagentStreamEmitter) Observer(stage string, index int, model string) adapter.StreamObserver {
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

func optionalFloatField(raw map[string]any, name string) (float64, bool, error) {
	value, ok := raw[name]
	if !ok {
		return 0, false, nil
	}
	switch v := value.(type) {
	case float64:
		return v, true, nil
	case int:
		return float64(v), true, nil
	case json.Number:
		parsed, err := v.Float64()
		if err != nil {
			return 0, true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent numeric field must be a number", Context: name}
		}
		return parsed, true, nil
	default:
		return 0, true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent numeric field must be a number", Context: name}
	}
}

func optionalStringField(raw map[string]any, name string, maxLen int) (string, bool, error) {
	value, ok := raw[name]
	if !ok {
		return "", false, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent string field must be a string", Context: name}
	}
	if maxLen > 0 && len(text) > maxLen {
		return "", true, &adapter.AdapterError{Status: 400, Message: "trustedrouter/subagent string field is too long", Context: name}
	}
	return text, true, nil
}
