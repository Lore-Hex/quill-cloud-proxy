package trustedrouter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// priorityEligibilityMaxInputTokens mirrors the router's frozen Stage C
// priority bucket. Above this boundary the enclave declines the optimization;
// the synchronous router remains authoritative for selection.
const priorityEligibilityMaxInputTokens = 32_768

// normalizedRoutingInputs reproduces the router-owned canonical normalization
// for the narrow Stage-C pilot cohort. Inputs whose router normalization cannot
// be represented exactly here are ineligible and take synchronous authorize.
func normalizedRoutingInputs(req *qtypes.OpenAIChatRequest, routeType, region string) ([]byte, bool) {
	if req == nil || (routeType != "chat.completions" && routeType != "responses") || len(req.Models) != 0 ||
		req.InferenceReceipt.Requested || req.AdditionalCostReservationMicrodollars != 0 ||
		req.ResponseModel != "" || strings.HasPrefix(req.Model, "trustedrouter/") {
		return nil, false
	}
	if EstimateInputTokens(req) > priorityEligibilityMaxInputTokens {
		return nil, false
	}
	provider := req.Provider
	if provider == nil || provider.Sort != nil || len(provider.Options) != 0 || len(provider.Quantizations) != 0 ||
		provider.MinPrivacy != "" || provider.Country != "" || provider.HeadquartersCountry != "" ||
		provider.ProviderCountry != "" || provider.ZDR != nil {
		return nil, false
	}
	usageType := firstNonEmpty(provider.Usage, provider.UsageType, provider.Billing)
	if !strings.EqualFold(usageType, "credits") {
		return nil, false
	}
	allowFallbacks := true
	if provider.AllowFallbacks != nil {
		allowFallbacks = *provider.AllowFallbacks
	}
	if req.AllowFallbacks != nil {
		allowFallbacks = *req.AllowFallbacks
	}
	promptPrice, completionPrice, ok := normalizedMaximumPrices(provider.MaxPrice)
	if !ok {
		return nil, false
	}
	var jurisdiction any
	if value := strings.ToLower(strings.TrimSpace(provider.Jurisdiction)); value != "" {
		jurisdiction = value
	}
	preferences := map[string]any{
		"allow_fallbacks": allowFallbacks,
		"data_collection": strings.ToLower(strings.TrimSpace(provider.DataCollection)),
		"ignore":          normalizedStrings(provider.Ignore),
		"max_completion_price_microdollars_per_million_tokens": completionPrice,
		"max_prompt_price_microdollars_per_million_tokens":     promptPrice,
		"min_privacy_rank":      0,
		"only":                  normalizedStrings(provider.Only),
		"order":                 normalizedStrings(provider.Order),
		"privacy_requirements":  []string{},
		"provider_jurisdiction": jurisdiction,
		"requested_parameters":  normalizedStrings(req.RequestedParameters),
		"require_parameters":    provider.RequireParameters != nil && *provider.RequireParameters,
		"sort":                  nil,
		"sort_partition":        "model",
		"usage_type":            "Credits",
	}
	var serviceTier any
	if value := strings.ToLower(strings.TrimSpace(req.ServiceTier)); value != "" {
		serviceTier = value
	}
	canonical := map[string]any{
		"fallback_policy":             allowFallbacks,
		"model_ids":                   []string{req.Model},
		"models_fallback_present":     false,
		"preferences":                 preferences,
		"priority_eligibility_bucket": "eligible",
		"region":                      region,
		"route_type":                  routeType,
		"service_tier":                serviceTier,
		"usage_type":                  "Credits",
	}
	body, err := json.Marshal(canonical)
	if err != nil {
		return nil, false
	}
	return body, true
}

func normalizedMaximumPrices(maxPrice map[string]any) (prompt, completion any, ok bool) {
	if len(maxPrice) == 0 {
		return nil, nil, true
	}
	for key, value := range maxPrice {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "prompt", "input":
			if prompt != nil {
				return nil, nil, false
			}
			prompt = value
		case "completion", "output":
			if completion != nil {
				return nil, nil, false
			}
			completion = value
		default:
			return nil, nil, false
		}
	}
	return prompt, completion, true
}

// RoutingPolicyHash computes the router-canonical Stage-C routing-policy hash.
// The boolean is false when the request is outside the locally admissible
// cohort and must take synchronous authorization.
func RoutingPolicyHash(req *qtypes.OpenAIChatRequest, routeType, region string) (string, bool) {
	return routingPolicyHash(req, routeType, region)
}

func routingPolicyHash(req *qtypes.OpenAIChatRequest, routeType, region string) (string, bool) {
	canonical, eligible := normalizedRoutingInputs(req, routeType, region)
	if !eligible {
		return "", false
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), true
}

func normalizedStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
