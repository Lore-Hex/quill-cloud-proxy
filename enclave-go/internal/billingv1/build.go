package billingv1

import (
	"encoding/json"
	"sort"
)

// Endpoint supplies effective customer prices at freeze time, without consulting
// a catalog. Cached tier prices may be absent; explicit zero remains zero.
type Endpoint struct {
	ID                    string         `json:"id" check:"identity"`
	Provider              string         `json:"provider" literal:"openai|anthropic"`
	ModelID               string         `json:"model_id" check:"identity"`
	UsageType             string         `json:"usage_type" literal:"Credits"`
	InputMicroPerMillion  int64          `json:"prompt_price_microdollars_per_million_tokens"`
	OutputMicroPerMillion int64          `json:"completion_price_microdollars_per_million_tokens"`
	RequestFeeMicro       int64          `json:"request_price_microdollars"`
	Tiers                 []EndpointTier `json:"price_tiers" bounds:"0,64"`
}
type EndpointTier struct {
	MaxPromptTokens            *int64 `json:"max_prompt_tokens"`
	InputMicroPerMillion       int64  `json:"prompt_price_microdollars_per_million_tokens"`
	OutputMicroPerMillion      int64  `json:"completion_price_microdollars_per_million_tokens"`
	CachedInputMicroPerMillion *int64 `json:"prompt_cached_price_microdollars_per_million_tokens"`
}

func ParseEndpoint(raw []byte) (Endpoint, error) {
	var v Endpoint
	err := parseModel(raw, &v, "invalid_builder")
	return v, err
}

// BuildSnapshot copies and sorts endpoints, resolves effective cache prices once,
// and validates the complete frozen program. No mutable input is retained.
func BuildSnapshot(endpoints []Endpoint, requested Eligibility) (Snapshot, error) {
	if err := RequireEligible(requested); err != nil {
		return Snapshot{}, err
	}
	data := snapshotData{V: 1, Kind: "credits_endpoint", MinimumCharge: "one_micro_if_positive", TierBasis: "total_prompt", TierBoundary: "inclusive", TierFallback: "last_tier", Candidates: []Candidate{}}
	for _, e := range endpoints {
		if err := validateGo(e, "invalid_builder"); err != nil {
			return Snapshot{}, err
		}
		rates, err := freezeRates(e.Provider, e.InputMicroPerMillion, e.OutputMicroPerMillion, nil)
		if err != nil {
			return Snapshot{}, err
		}
		c := Candidate{EndpointID: e.ID, Provider: e.Provider, ModelID: e.ModelID, UsageType: e.UsageType, PriceHistoryVersion: 1, Rates: rates, Tiers: []Tier{}, RequestFeeMicro: e.RequestFeeMicro, Rounding: "half_up_per_million", PromptConvention: "includes_cache", OutputConvention: "includes_reasoning"}
		if e.Provider == "anthropic" {
			c.PromptConvention = "excludes_cache"
		}
		for _, t := range e.Tiers {
			r, err := freezeRates(e.Provider, t.InputMicroPerMillion, t.OutputMicroPerMillion, t.CachedInputMicroPerMillion)
			if err != nil {
				return Snapshot{}, err
			}
			c.Tiers = append(c.Tiers, Tier{MaxPromptTokens: t.MaxPromptTokens, Rates: r})
		}
		data.Candidates = append(data.Candidates, c)
	}
	sort.Slice(data.Candidates, func(i, j int) bool { return data.Candidates[i].EndpointID < data.Candidates[j].EndpointID })
	raw, err := json.Marshal(data)
	if err != nil {
		return Snapshot{}, err
	}
	return ParseSnapshot(raw)
}
func freezeRates(provider string, input, output int64, cached *int64) (Rates, error) {
	divisor := int64(2)
	if provider == "anthropic" {
		divisor = 10
	}
	read, err := roundRatioEven(input, 1, divisor)
	if err != nil {
		return Rates{}, err
	}
	if cached != nil {
		read = *cached
	}
	write, err := roundRatioEven(input, 5, 4)
	if err != nil {
		return Rates{}, err
	}
	return Rates{InputMicroPerMillion: input, OutputMicroPerMillion: output, CachedInputMicroPerMillion: read, CacheCreationMicroPerMillion: write}, nil
}

// Catalog cache multipliers use Decimal's half-even, unlike usage components.
// Divide first so an intermediate product cannot reject a representable rate.
func roundRatioEven(value, numerator, denominator int64) (int64, error) {
	base, err := checkedMultiply(value/denominator, numerator)
	if err != nil {
		return 0, err
	}
	remainder, err := checkedMultiply(value%denominator, numerator)
	if err != nil {
		return 0, err
	}
	base, err = checkedAdd(base, remainder/denominator)
	if err != nil {
		return 0, err
	}
	remainder %= denominator
	if remainder*2 > denominator || (remainder*2 == denominator && base%2 == 1) {
		return checkedAdd(base, 1)
	}
	return base, nil
}
