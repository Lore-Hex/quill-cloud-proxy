package main

import "strings"

func socratesProviderUsage(details map[string]any) map[string]any {
	if len(details) == 0 {
		return nil
	}
	workers := providerUsageCallList(details["worker_attempts"])
	advisorAll := providerUsageCallList(details["advisor_attempts"])
	advisors, advisorFinal := splitProviderUsageCalls(advisorAll, "socrates.advisor_final")
	out := map[string]any{
		"router":                        "trustedrouter/socrates",
		"version":                       details["version"],
		"selected_model":                details["selected_model"],
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
		"worker_attempts":               workers,
		"advisor_attempts":              advisors,
		"advisor_final_attempts":        advisorFinal,
		"cost_microdollars":             details["cost_microdollars"],
		"contains_prompt_or_completion": false,
	}
	return pruneEmptyProviderUsage(out)
}

func fusionProviderUsage(details map[string]any) map[string]any {
	if len(details) == 0 {
		return nil
	}
	panel := providerUsageCallList(details["panel"])
	judgeAttempts := providerUsageCallList(details["judge_attempts"])
	finalAttempts := providerUsageCallList(details["final_attempts"])
	out := map[string]any{
		"router":                        "trustedrouter/synth",
		"preset":                        details["preset"],
		"selection_strategy":            details["selection_strategy"],
		"selected_model":                details["selected_model"],
		"panel_attempt_count":           len(panel),
		"judge_attempt_count":           len(judgeAttempts),
		"final_attempt_count":           len(finalAttempts),
		"panel_models":                  providerUsageModels(panel),
		"judge_models":                  providerUsageModels(judgeAttempts),
		"final_models":                  providerUsageModels(finalAttempts),
		"panel":                         panel,
		"judge_attempts":                judgeAttempts,
		"final_attempts":                finalAttempts,
		"cost_microdollars":             details["cost_microdollars"],
		"contains_prompt_or_completion": false,
	}
	return pruneEmptyProviderUsage(out)
}

func providerUsageCallList(value any) []map[string]any {
	switch items := value.(type) {
	case []map[string]any:
		out := make([]map[string]any, 0, len(items))
		for _, item := range items {
			out = append(out, providerUsageCall(item))
		}
		return out
	case []any:
		out := make([]map[string]any, 0, len(items))
		for _, raw := range items {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, providerUsageCall(item))
		}
		return out
	default:
		return nil
	}
}

func providerUsageCall(detail map[string]any) map[string]any {
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
		"usage_estimated",
		"elapsed_ms",
		"cost_microdollars",
		"overthinking_rescue",
		"overthinking_route_type",
		"overthinking_model",
		"aborted_thinking_tokens",
	} {
		if value, ok := detail[key]; ok && !providerUsageEmpty(value) {
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
	if details, ok := m["socrates"].(map[string]any); ok {
		out["socrates"] = socratesProviderUsage(details)
	}
	if details, ok := m["synth"].(map[string]any); ok {
		out["synth"] = fusionProviderUsage(details)
	}
	return pruneEmptyProviderUsage(out)
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
