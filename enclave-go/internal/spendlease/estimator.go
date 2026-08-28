package spendlease

import (
	"errors"
	"math"
)

const microPerMillion = int64(1_000_000)

func Estimate(catalog Catalog, request EstimateRequest) (*int64, error) {
	if request.EstimatedInputTokens < 0 {
		return nil, errors.New("spendlease: negative token estimate")
	}
	outputTokens := int64(512)
	if request.MaxTokens != nil {
		outputTokens = *request.MaxTokens
	}
	if outputTokens < 0 {
		return nil, errors.New("spendlease: negative max_tokens")
	}
	selectedEndpoint := make(map[string]bool)
	var maximum int64
	found := false
	for _, candidate := range catalog.Candidates {
		if selectedEndpoint[candidate.EndpointID] || !applies(candidate, request) {
			continue
		}
		if candidate.PriceTierMaxInputTokens != nil && request.EstimatedInputTokens > *candidate.PriceTierMaxInputTokens {
			continue
		}
		selectedEndpoint[candidate.EndpointID] = true
		inputCost, err := tokenCost(candidate.InputPriceMicroPerMTok, request.EstimatedInputTokens)
		if err != nil {
			return nil, err
		}
		outputCost, err := tokenCost(candidate.OutputPriceMicroPerMTok, outputTokens)
		if err != nil {
			return nil, err
		}
		if candidate.RequestPriceMicro < 0 || inputCost > math.MaxInt64-candidate.RequestPriceMicro || outputCost > math.MaxInt64-candidate.RequestPriceMicro-inputCost {
			return nil, errors.New("spendlease: invalid or overflowing price")
		}
		total := candidate.RequestPriceMicro + inputCost + outputCost
		hasPositiveCharge := candidate.RequestPriceMicro > 0 ||
			(request.EstimatedInputTokens > 0 && candidate.InputPriceMicroPerMTok > 0) ||
			(outputTokens > 0 && candidate.OutputPriceMicroPerMTok > 0)
		if hasPositiveCharge && total < 1 {
			total = 1
		}
		if !found || total > maximum {
			maximum = total
		}
		found = true
	}
	if !found {
		return nil, nil
	}
	return &maximum, nil
}

func applies(candidate Candidate, request EstimateRequest) bool {
	if candidate.EndpointID == "" || candidate.Model != request.Model || candidate.RouteType != request.RouteType || candidate.Region != request.Region || candidate.ServiceTier != request.ServiceTier {
		return false
	}
	if len(request.ProviderConstraints) == 0 {
		return true
	}
	for _, provider := range request.ProviderConstraints {
		if provider == candidate.Provider {
			return true
		}
	}
	return false
}

// tokenCost mirrors money.py:57 integer micro-per-million ROUND_HALF_UP.
// The server's one-microdollar floor is applied to the complete endpoint cost
// above, matching gateway.py's _endpoint_cost_microdollars.
func tokenCost(rate, tokens int64) (int64, error) {
	if rate < 0 || tokens < 0 {
		return 0, errors.New("spendlease: negative price or token count")
	}
	if rate == 0 || tokens == 0 {
		return 0, nil
	}
	if tokens > (math.MaxInt64-microPerMillion/2)/rate {
		return 0, errors.New("spendlease: token price overflow")
	}
	cost := (rate*tokens + microPerMillion/2) / microPerMillion
	return cost, nil
}
