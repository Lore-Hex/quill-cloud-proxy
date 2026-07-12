package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func annotateSettledResponseMetadata(
	body []byte,
	authorization *trustedrouter.Authorization,
	settlement *trustedrouter.SettleResult,
	selectedRoute *selectedRouteTracker,
	invokeOptions []llm.InvokeOptions,
	result adapter.StreamResult,
	includeOpenRouterMetadata bool,
) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	usage, _ := payload["usage"].(map[string]any)
	if usage == nil {
		usage = map[string]any{}
		payload["usage"] = usage
	}

	selectedModel := ""
	if selectedRoute != nil {
		selectedModel = selectedRoute.Model("", authorization)
	}
	if settlement != nil && settlement.Model != "" {
		selectedModel = settlement.Model
	}
	selectedEndpoint := ""
	selectedProvider := ""
	if selectedRoute != nil {
		selectedEndpoint = selectedRoute.Endpoint("", authorization)
		selectedProvider = selectedRoute.Provider("", authorization)
	}
	if settlement != nil && settlement.Provider != "" {
		selectedProvider = settlement.Provider
	}
	candidateCount := routeCandidateCount(authorization, invokeOptions)
	attemptCount := 0
	fallbackCount := 0
	if selectedRoute != nil {
		attemptCount = selectedRoute.AttemptCount()
		fallbackCount = selectedRoute.FallbackCount()
	}
	if attemptCount == 0 && candidateCount > 0 {
		attemptCount = 1
	}

	routeUsage := map[string]any{
		"router":                        "direct",
		"selected_model":                selectedModel,
		"selected_provider":             selectedProvider,
		"selected_endpoint":             selectedEndpoint,
		"fallback_candidate_count":      candidateCount,
		"upstream_attempt_count":        attemptCount,
		"fallback_attempt_count":        fallbackCount,
		"contains_prompt_or_completion": false,
	}
	cacheRead := 0
	if result.Usage != nil {
		cacheRead = result.Usage.CacheReadInputTokens
		cacheCreated := result.Usage.CacheCreationInputTokens
		if cacheRead > 0 {
			usage["cache_read_input_tokens"] = cacheRead
			routeUsage["cache_read_input_tokens"] = cacheRead
		}
		if cacheCreated > 0 {
			usage["cache_creation_input_tokens"] = cacheCreated
			routeUsage["cache_creation_input_tokens"] = cacheCreated
		}
		if result.Usage.ReasoningTokens > 0 {
			routeUsage["reasoning_tokens"] = result.Usage.ReasoningTokens
		}
	}
	if promptTokens := tokenCountFromUsage(usage, "prompt_tokens", "input_tokens"); promptTokens > 0 {
		uncached := promptTokens - cacheRead
		if uncached < 0 {
			uncached = 0
		}
		usage["uncached_input_tokens"] = uncached
		routeUsage["uncached_input_tokens"] = uncached
	}
	if outputTokens := tokenCountFromUsage(usage, "completion_tokens", "output_tokens"); outputTokens > 0 {
		routeUsage["output_tokens"] = outputTokens
	}
	if settlement != nil {
		usage["cost_microdollars"] = settlement.CostMicrodollars
		usage["total_cost_microdollars"] = settlement.CostMicrodollars
		routeUsage["cost_microdollars"] = settlement.CostMicrodollars
		routeUsage["total_cost_microdollars"] = settlement.CostMicrodollars
		if settlement.GenerationID != "" {
			routeUsage["generation_id"] = settlement.GenerationID
		}
		if settlement.UsageType != "" {
			routeUsage["usage_type"] = settlement.UsageType
		}
		if settlement.Region != "" {
			routeUsage["region"] = settlement.Region
		}
	}
	routeUsage = pruneEmptyProviderUsage(routeUsage)
	usage["provider_usage"] = routeUsage
	payload["trustedrouter"] = mergeTrustedRouterRouting(payload["trustedrouter"], routeUsage)
	if includeOpenRouterMetadata {
		payload["openrouter_metadata"] = openRouterRoutingMetadata(
			authorization,
			selectedRoute,
			invokeOptions,
		)
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func openRouterRoutingMetadata(
	authorization *trustedrouter.Authorization,
	selectedRoute *selectedRouteTracker,
	invokeOptions []llm.InvokeOptions,
) map[string]any {
	requested := ""
	region := ""
	usageType := ""
	if authorization != nil {
		requested = authorization.RequestedModel
		if requested == "" {
			requested = authorization.Model
		}
		region = authorization.Region
		usageType = authorization.UsageType
	}
	selectedModel := ""
	selectedProvider := ""
	selectedEndpoint := ""
	if selectedRoute != nil {
		selectedModel = selectedRoute.Model("", authorization)
		selectedProvider = selectedRoute.Provider("", authorization)
		selectedEndpoint = selectedRoute.Endpoint("", authorization)
	}
	if authorization != nil {
		if selectedModel == "" {
			selectedModel = authorization.Model
		}
		if selectedProvider == "" {
			selectedProvider = authorization.Provider
		}
		if selectedEndpoint == "" {
			selectedEndpoint = authorization.EndpointID
		}
	}
	attempt := 0
	fallbacks := 0
	if selectedRoute != nil {
		attempt = selectedRoute.AttemptCount()
		fallbacks = selectedRoute.FallbackCount()
	}
	if attempt == 0 && authorization != nil {
		attempt = 1
	}
	strategy := "direct"
	if fallbacks > 0 {
		strategy = "fallback"
	} else if strings.HasPrefix(requested, "trustedrouter/") {
		strategy = "alias"
	}
	available := make([]map[string]any, 0, routeCandidateCount(authorization, invokeOptions))
	if authorization != nil && len(authorization.RouteCandidates) > 0 {
		for _, candidate := range authorization.RouteCandidates {
			provider := candidate.ProviderName
			if provider == "" {
				provider = candidate.Provider
			}
			available = append(available, map[string]any{
				"provider": provider,
				"model":    candidate.Model,
				"selected": candidate.EndpointID == selectedEndpoint,
			})
		}
	} else if authorization != nil {
		provider := authorization.ProviderName
		if provider == "" {
			provider = authorization.Provider
		}
		available = append(available, map[string]any{
			"provider": provider,
			"model":    selectedModel,
			"selected": true,
		})
	}
	return map[string]any{
		"requested": requested,
		"strategy":  strategy,
		"region":    region,
		"summary": fmt.Sprintf(
			"available=%d, selected=%s",
			len(available),
			selectedProvider,
		),
		"attempt": attempt,
		"is_byok": strings.EqualFold(usageType, "BYOK"),
		"endpoints": map[string]any{
			"total":     len(available),
			"available": available,
		},
	}
}

func applyUsageProviderSummary(usage map[string]any, providerUsage map[string]any) {
	if len(usage) == 0 || len(providerUsage) == 0 {
		return
	}
	for _, key := range []string{
		"orchestration",
		"subcall_count",
		"panel_count",
		"advisor_call_count",
		"subagent_call_count",
		"total_cost_microdollars",
	} {
		if value, ok := providerUsage[key]; ok && !providerUsageEmpty(value) {
			usage[key] = value
		}
	}
}

func routeCandidateCount(authorization *trustedrouter.Authorization, invokeOptions []llm.InvokeOptions) int {
	if len(invokeOptions) > 0 {
		return len(invokeOptions)
	}
	if authorization != nil && len(authorization.RouteCandidates) > 0 {
		return len(authorization.RouteCandidates)
	}
	if authorization != nil {
		return 1
	}
	return 0
}

func tokenCountFromUsage(usage map[string]any, keys ...string) int {
	for _, key := range keys {
		if value, ok := usage[key]; ok {
			if n := providerUsageInt(value); n > 0 {
				return n
			}
		}
	}
	return 0
}

func mergeTrustedRouterRouting(existing any, routeUsage map[string]any) map[string]any {
	out, _ := existing.(map[string]any)
	if out == nil {
		out = map[string]any{}
	}
	out["routing"] = pruneEmptyProviderUsage(map[string]any{
		"selected_model":           routeUsage["selected_model"],
		"selected_provider":        routeUsage["selected_provider"],
		"selected_endpoint":        routeUsage["selected_endpoint"],
		"fallback_candidate_count": routeUsage["fallback_candidate_count"],
		"upstream_attempt_count":   routeUsage["upstream_attempt_count"],
		"fallback_attempt_count":   routeUsage["fallback_attempt_count"],
	})
	return out
}
