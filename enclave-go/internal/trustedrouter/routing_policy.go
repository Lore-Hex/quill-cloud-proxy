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

// normalizedRoutingInputs is serialized through a map so encoding/json emits
// lexicographically sorted keys, matching the router's canonical JSON. This is
// only an applicability check: the router recomputes and enforces the hash.
func normalizedRoutingInputs(req *qtypes.OpenAIChatRequest, routeType, region string) ([]byte, bool) {
	if req == nil || (routeType != "chat.completions" && routeType != "responses") || len(req.Models) != 0 ||
		req.InferenceReceipt.Requested || req.AdditionalCostReservationMicrodollars != 0 ||
		req.ResponseModel != "" || strings.HasPrefix(req.Model, "trustedrouter/") {
		return nil, false
	}
	inputTokens := EstimateInputTokens(req)
	if inputTokens > priorityEligibilityMaxInputTokens {
		return nil, false
	}
	provider := req.Provider
	if provider == nil || provider.Sort != nil || len(provider.Options) != 0 || len(provider.Quantizations) != 0 {
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
	maxPrice := provider.MaxPrice
	if maxPrice == nil {
		maxPrice = map[string]any{}
	}
	canonical := map[string]any{
		"allow_fallbacks":      allowFallbacks,
		"country":              strings.ToLower(strings.TrimSpace(provider.Country)),
		"data_collection":      strings.ToLower(strings.TrimSpace(provider.DataCollection)),
		"headquarters_country": strings.ToLower(strings.TrimSpace(provider.HeadquartersCountry)),
		"ignore":               normalizedStrings(provider.Ignore),
		"jurisdiction":         strings.ToLower(strings.TrimSpace(provider.Jurisdiction)),
		"max_price":            maxPrice,
		"min_privacy":          strings.ToLower(strings.TrimSpace(provider.MinPrivacy)),
		"model":                req.Model,
		"only":                 normalizedStrings(provider.Only),
		"order":                normalizedStrings(provider.Order),
		"priority_eligible":    true,
		"provider_country":     strings.ToLower(strings.TrimSpace(provider.ProviderCountry)),
		"region":               region,
		"requested_parameters": normalizedStrings(req.RequestedParameters),
		"require_parameters":   provider.RequireParameters,
		"route_type":           routeType,
		"service_tier":         strings.ToLower(strings.TrimSpace(req.ServiceTier)),
		"usage_type":           "credits",
		"zdr":                  provider.ZDR,
	}
	body, err := json.Marshal(canonical)
	if err != nil {
		return nil, false
	}
	return body, true
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
