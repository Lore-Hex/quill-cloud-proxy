package main

import (
	"encoding/json"
	"strings"
)

func advisorProviderUsage(details map[string]any) map[string]any {
	if len(details) == 0 {
		return nil
	}
	primitive := providerUsageOrDefault(details["primitive"], trustedRouterAdvisorModel)
	workers := providerUsageCallList(details["worker_attempts"], primitive)
	advisorAll := providerUsageCallList(details["advisor_attempts"], primitive)
	advisors, advisorFinal := splitProviderUsageCalls(advisorAll, "advisor.advisor_final")
	allCalls := providerUsageConcat(workers, advisors, advisorFinal)
	out := map[string]any{
		"orchestration":                 true,
		"router":                        providerUsageOrDefault(details["router"], primitive),
		"primitive":                     primitive,
		"version":                       details["version"],
		"selected_model":                details["selected_model"],
		"subcall_count":                 providerUsageSubcallCount(allCalls),
		"depth_initial":                 details["depth_initial"],
		"max_get_advice_calls":          details["max_get_advice_calls"],
		"advice_call_count":             details["advice_call_count"],
		"advice_budget_exhausted":       details["advice_budget_exhausted"],
		"worker_attempt_count":          len(workers),
		"advisor_attempt_count":         len(advisors),
		"advisor_final_attempt_count":   len(advisorFinal),
		"worker_models":                 providerUsageModels(workers),
		"advisor_models":                providerUsageModels(advisors),
		"advisor_final_models":          providerUsageModels(advisorFinal),
		"reasoning_tokens":              providerUsageIntSum(allCalls, "reasoning_tokens"),
		"cache_read_input_tokens":       providerUsageIntSum(allCalls, "cache_read_input_tokens"),
		"cache_creation_input_tokens":   providerUsageIntSum(allCalls, "cache_creation_input_tokens"),
		"worker_attempts":               workers,
		"advisor_attempts":              advisors,
		"advisor_final_attempts":        advisorFinal,
		"cost_microdollars":             details["cost_microdollars"],
		"total_cost_microdollars":       details["cost_microdollars"],
		"contains_prompt_or_completion": false,
	}
	return pruneEmptyProviderUsage(out)
}

func advisorPublicProviderUsage(details map[string]any) map[string]any {
	if !advisorHidePublicMetadata(details) {
		return advisorProviderUsage(details)
	}
	full := advisorProviderUsage(details)
	if len(full) == 0 {
		return nil
	}
	out := map[string]any{
		"orchestration":                 true,
		"router":                        providerUsageOrDefault(details["router"], trustedRouterAdvisorModel),
		"primitive":                     providerUsageOrDefault(details["primitive"], trustedRouterAdvisorModel),
		"version":                       details["version"],
		"subcall_count":                 full["subcall_count"],
		"depth_initial":                 details["depth_initial"],
		"max_get_advice_calls":          details["max_get_advice_calls"],
		"advice_call_count":             details["advice_call_count"],
		"advice_budget_exhausted":       details["advice_budget_exhausted"],
		"worker_attempt_count":          full["worker_attempt_count"],
		"advisor_attempt_count":         full["advisor_attempt_count"],
		"advisor_final_attempt_count":   full["advisor_final_attempt_count"],
		"reasoning_tokens":              full["reasoning_tokens"],
		"cache_read_input_tokens":       full["cache_read_input_tokens"],
		"cache_creation_input_tokens":   full["cache_creation_input_tokens"],
		"cost_microdollars":             full["cost_microdollars"],
		"total_cost_microdollars":       full["total_cost_microdollars"],
		"contains_prompt_or_completion": false,
	}
	return pruneEmptyProviderUsage(out)
}

func fusionProviderUsage(details map[string]any) map[string]any {
	if len(details) == 0 {
		return nil
	}
	primitive := providerUsageOrDefault(details["primitive"], trustedRouterSynthModel)
	panel := providerUsageCallList(details["panel"], primitive)
	judgeAttempts := providerUsageCallList(details["judge_attempts"], primitive)
	finalAttempts := providerUsageCallList(details["final_attempts"], primitive)
	selectorAttempts := providerUsageCallList(details["selector_attempts"], primitive)
	mapperAttempts := providerUsageCallList(details["mapper_attempts"], primitive)
	parts := providerUsageCallList(details["parts"], primitive)
	reducerAttempts := providerUsageCallList(details["reducer_attempts"], primitive)
	allCalls := providerUsageConcat(panel, judgeAttempts, finalAttempts, selectorAttempts, mapperAttempts, parts, reducerAttempts)
	out := map[string]any{
		"orchestration":                 true,
		"router":                        providerUsageOrDefault(details["router"], primitive),
		"primitive":                     primitive,
		"preset":                        details["preset"],
		"selection_strategy":            details["selection_strategy"],
		"selected_model":                details["selected_model"],
		"subcall_count":                 providerUsageSubcallCount(allCalls),
		"panel_count":                   len(panel),
		"panel_attempt_count":           len(panel),
		"judge_attempt_count":           len(judgeAttempts),
		"final_attempt_count":           len(finalAttempts),
		"panel_models":                  providerUsageModels(panel),
		"judge_models":                  providerUsageModels(judgeAttempts),
		"final_models":                  providerUsageModels(finalAttempts),
		"selector_attempt_count":        len(selectorAttempts),
		"selector_models":               providerUsageModels(selectorAttempts),
		"selector_attempts":             selectorAttempts,
		"mapper_attempt_count":          len(mapperAttempts),
		"part_attempt_count":            len(parts),
		"reducer_attempt_count":         len(reducerAttempts),
		"mapper_models":                 providerUsageModels(mapperAttempts),
		"part_models":                   providerUsageModels(parts),
		"reducer_models":                providerUsageModels(reducerAttempts),
		"reasoning_tokens":              providerUsageIntSum(allCalls, "reasoning_tokens"),
		"cache_read_input_tokens":       providerUsageIntSum(allCalls, "cache_read_input_tokens"),
		"cache_creation_input_tokens":   providerUsageIntSum(allCalls, "cache_creation_input_tokens"),
		"mapper_attempts":               mapperAttempts,
		"parts":                         parts,
		"reducer_attempts":              reducerAttempts,
		"panel":                         panel,
		"judge_attempts":                judgeAttempts,
		"final_attempts":                finalAttempts,
		"cost_microdollars":             details["cost_microdollars"],
		"total_cost_microdollars":       details["cost_microdollars"],
		"contains_prompt_or_completion": false,
	}
	return pruneEmptyProviderUsage(out)
}

func subagentProviderUsage(details map[string]any) map[string]any {
	if len(details) == 0 {
		return nil
	}
	primitive := providerUsageOrDefault(details["primitive"], trustedRouterSubagentModel)
	controllers := providerUsageCallList(details["controller_attempts"], primitive)
	workers := providerUsageCallList(details["subagent_attempts"], primitive)
	allCalls := providerUsageConcat(controllers, workers)
	out := map[string]any{
		"orchestration":                 true,
		"router":                        providerUsageOrDefault(details["router"], primitive),
		"primitive":                     primitive,
		"version":                       details["version"],
		"selected_model":                details["selected_model"],
		"subcall_count":                 providerUsageSubcallCount(allCalls),
		"controller_model":              details["controller_model"],
		"worker_model":                  details["worker_model"],
		"depth_initial":                 details["depth_initial"],
		"max_subagent_calls":            details["max_subagent_calls"],
		"subagent_call_count":           details["subagent_call_count"],
		"subagent_budget_exhausted":     details["subagent_budget_exhausted"],
		"controller_attempt_count":      len(controllers),
		"subagent_attempt_count":        len(workers),
		"controller_models":             providerUsageModels(controllers),
		"subagent_models":               providerUsageModels(workers),
		"reasoning_tokens":              providerUsageIntSum(allCalls, "reasoning_tokens"),
		"cache_read_input_tokens":       providerUsageIntSum(allCalls, "cache_read_input_tokens"),
		"cache_creation_input_tokens":   providerUsageIntSum(allCalls, "cache_creation_input_tokens"),
		"controller_attempts":           controllers,
		"subagent_attempts":             workers,
		"cost_microdollars":             details["cost_microdollars"],
		"total_cost_microdollars":       details["cost_microdollars"],
		"contains_prompt_or_completion": false,
	}
	return pruneEmptyProviderUsage(out)
}

func providerUsageCallList(value any, primitive string) []map[string]any {
	switch items := value.(type) {
	case []map[string]any:
		out := make([]map[string]any, 0, len(items))
		for _, item := range items {
			out = append(out, providerUsageCall(item, primitive))
		}
		return out
	case []any:
		out := make([]map[string]any, 0, len(items))
		for _, raw := range items {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, providerUsageCall(item, primitive))
		}
		return out
	default:
		return nil
	}
}

func providerUsageCall(detail map[string]any, primitive string) map[string]any {
	if len(detail) == 0 {
		return nil
	}
	out := map[string]any{}
	for _, key := range []string{
		"route_type",
		"model",
		"endpoint",
		"provider",
		"generation_id",
		"finish_reason",
		"input_tokens",
		"output_tokens",
		"reasoning_tokens",
		"cache_read_input_tokens",
		"cache_creation_input_tokens",
		"usage_estimated",
		"elapsed_ms",
		"cost_microdollars",
		"overthinking_rescue",
		"overthinking_route_type",
		"overthinking_model",
		"aborted_thinking_tokens",
	} {
		if value, ok := detail[key]; ok && !providerUsageEmpty(value) {
			if key == "route_type" {
				value = publicOrchestrationRouteType(value, primitive)
			}
			out[key] = value
		}
	}
	if nested := providerUsageNested(detail["orchestration"]); len(nested) > 0 {
		out["orchestration"] = nested
	}
	return pruneEmptyProviderUsage(out)
}

func splitProviderUsageCalls(items []map[string]any, routeType string) ([]map[string]any, []map[string]any) {
	var other []map[string]any
	var matching []map[string]any
	for _, item := range items {
		if strings.TrimSpace(providerUsageString(item["route_type"])) == routeType {
			matching = append(matching, item)
		} else {
			other = append(other, item)
		}
	}
	return other, matching
}

func providerUsageNested(value any) map[string]any {
	m, ok := value.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	out := map[string]any{}
	if details, ok := m["advisor"].(map[string]any); ok {
		out["advisor"] = advisorProviderUsage(details)
	}
	if details, ok := m["subagent"].(map[string]any); ok {
		out["subagent"] = subagentProviderUsage(details)
	}
	for _, key := range []string{"synth", "selector", "mapreduce"} {
		if details, ok := m[key].(map[string]any); ok {
			out[key] = fusionProviderUsage(details)
		}
	}
	return pruneEmptyProviderUsage(out)
}

func orchestrationDetailKey(details map[string]any, fallback string) string {
	if details == nil {
		return orchestrationKeyFromModel(fallback)
	}
	return orchestrationKeyFromModel(providerUsageOrDefault(details["primitive"], fallback))
}

func orchestrationKeyFromModel(model string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	model = strings.TrimPrefix(model, "trustedrouter/")
	switch model {
	case "", "fusion", "fusion-code", "synth-code":
		return "synth"
	default:
		return model
	}
}

func fusionPrimitiveForMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case fusionModeSelector:
		return trustedRouterSelectorModel
	case fusionModeMapReduce:
		return trustedRouterMapReduceModel
	default:
		return trustedRouterSynthModel
	}
}

func providerUsageOrDefault(value any, fallback string) string {
	if out := strings.TrimSpace(providerUsageString(value)); out != "" {
		return out
	}
	return fallback
}

func publicOrchestrationRouteType(value any, primitive string) any {
	routeType := strings.TrimSpace(providerUsageString(value))
	if strings.HasPrefix(routeType, "fusion.") {
		suffix := strings.TrimPrefix(routeType, "fusion.")
		switch strings.TrimSpace(primitive) {
		case trustedRouterSelectorModel:
			if suffix == "selector" {
				return "selector.decision"
			}
			return "selector." + suffix
		case trustedRouterMapReduceModel:
			return "mapreduce." + strings.TrimPrefix(suffix, "mapreduce.")
		default:
			return "synth." + suffix
		}
	}
	if strings.HasPrefix(routeType, "subagent.") {
		return routeType
	}
	return value
}

func providerUsageModels(items []map[string]any) []string {
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		model := strings.TrimSpace(providerUsageString(item["model"]))
		if model == "" || seen[model] {
			continue
		}
		seen[model] = true
		out = append(out, model)
	}
	return out
}

func providerUsageConcat(groups ...[]map[string]any) []map[string]any {
	total := 0
	for _, group := range groups {
		total += len(group)
	}
	out := make([]map[string]any, 0, total)
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

func providerUsageSubcallCount(items []map[string]any) int {
	total := 0
	for _, item := range items {
		if nested := providerUsageNestedSubcallCount(item["orchestration"]); nested > 0 {
			total += nested
			continue
		}
		total++
	}
	return total
}

func providerUsageNestedSubcallCount(value any) int {
	nested, ok := value.(map[string]any)
	if !ok {
		return 0
	}
	total := 0
	for _, raw := range nested {
		details, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		count := providerUsageInt(details["subcall_count"])
		if count < 1 {
			count = 1
		}
		total += count
	}
	return total
}

func providerUsageIntSum(items []map[string]any, key string) int {
	total := 0
	for _, item := range items {
		total += providerUsageInt(item[key])
	}
	return total
}

func providerUsageInt(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		if out, err := typed.Int64(); err == nil {
			return int(out)
		}
	}
	return 0
}

func pruneEmptyProviderUsage(in map[string]any) map[string]any {
	for key, value := range in {
		if providerUsageEmpty(value) {
			delete(in, key)
		}
	}
	return in
}

func providerUsageEmpty(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	case []string:
		return len(typed) == 0
	case []map[string]any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	default:
		return false
	}
}

func providerUsageString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}
