package trustedrouter

import (
	"encoding/json"
	"math/big"
)

// CostMicrodollars mirrors stage_d.endpoint_cost_microdollars_from_candidate.
// Inputs are normalized UNCACHED tokens, as in the Python pricing primitive.
// This is reporting only; it must not replace settlement or cap accounting.
func (p CandidatePrice) CostMicrodollars(input, output, cached, creation, tierInput int) (int, bool) {
	if p.incompleteSnapshot || p.Rounding != "half_up_per_million" || p.PriceHistoryVersion != 1 || p.RequestFeeMicro < 0 {
		return 0, false
	}
	for _, count := range []int{input, output, cached, creation} {
		if count < 0 {
			return 0, false
		}
	}
	prompt := new(big.Int).SetInt64(int64(input))
	prompt.Add(prompt, big.NewInt(int64(cached)))
	prompt.Add(prompt, big.NewInt(int64(creation)))
	if tierInput > 0 && prompt.Cmp(big.NewInt(int64(tierInput))) >= 0 {
		prompt.SetInt64(int64(tierInput))
	}
	rates := p.Rates
	for _, tier := range p.Tiers {
		// Python uses the last tier even if no upper bound contains the prompt.
		rates = tier.Rates
		if tier.MaxPromptTokens == nil || prompt.Cmp(big.NewInt(*tier.MaxPromptTokens)) <= 0 {
			break
		}
	}
	cost := big.NewInt(p.RequestFeeMicro)
	positive := p.RequestFeeMicro > 0
	for _, component := range []struct {
		tokens int
		rate   int64
	}{
		{input, rates.InputMicroPerMillion}, {output, rates.OutputMicroPerMillion},
		{cached, rates.CachedInputMicroPerMillion}, {creation, rates.CacheCreationMicroPerMillion},
	} {
		if component.rate < 0 {
			return 0, false
		}
		positive = positive || (component.tokens > 0 && component.rate > 0)
		part := new(big.Int).Mul(big.NewInt(int64(component.tokens)), big.NewInt(component.rate))
		part.Add(part, big.NewInt(500_000))
		part.Quo(part, big.NewInt(1_000_000))
		cost.Add(cost, part)
	}
	if positive && cost.Sign() == 0 {
		cost.SetInt64(1)
	}
	if !cost.IsInt64() || int64(int(cost.Int64())) != cost.Int64() {
		return 0, false
	}
	return int(cost.Int64()), true
}

// Go literals specify their zero rates intentionally. Wire snapshots must prove
// that all price fields were present, including explicit zero fees and rates.
func (p *CandidatePrice) UnmarshalJSON(data []byte) error {
	type plain CandidatePrice
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	completeRates := func(raw json.RawMessage) bool {
		var rates map[string]*int64
		if json.Unmarshal(raw, &rates) != nil {
			return false
		}
		for _, key := range []string{"input_micro_per_million", "output_micro_per_million", "cached_input_micro_per_million", "cache_creation_micro_per_million"} {
			if rates[key] == nil {
				return false
			}
		}
		return true
	}
	var fee *int64
	_ = json.Unmarshal(fields["request_fee_micro"], &fee)
	decoded.incompleteSnapshot = fee == nil || !completeRates(fields["rates"])
	var tiers []map[string]json.RawMessage
	_ = json.Unmarshal(fields["tiers"], &tiers)
	for _, tier := range tiers {
		if !completeRates(tier["rates"]) {
			decoded.incompleteSnapshot = true
		}
	}
	*p = CandidatePrice(decoded)
	return nil
}
