package billingv1

import "math"

func checkedAdd(a, b int64) (int64, error) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, failure("arithmetic_overflow")
	}
	return a + b, nil
}
func checkedMultiply(a, b int64) (int64, error) {
	if a < 0 || b < 0 || (b != 0 && a > math.MaxInt64/b) {
		return 0, failure("arithmetic_overflow")
	}
	return a * b, nil
}

// RequireEligible returns the first exclusion in contract order, or a validation
// error for malformed facts. Use it for both requested and observed phases.
func RequireEligible(c Eligibility) error {
	if err := validateGo(c, "invalid_context"); err != nil {
		return err
	}
	if !c.Typed {
		return failure("untyped")
	}
	if c.UsageType != "Credits" {
		return failure("non_credits")
	}
	if c.Authority != "local" {
		return failure("settlement_authority")
	}
	if c.RouteType != "chat.completions" && c.RouteType != "responses" {
		return failure("unsupported_route")
	}
	if c.ServiceTier != nil && *c.ServiceTier != "default" {
		return failure("service_tier")
	}
	for _, f := range []struct {
		name     string
		excluded bool
	}{
		{"app_markup", c.AppMarkup != 0}, {"custom_markup", c.CustomMarkup != 0}, {"receipt_fee", c.ReceiptFee != 0}, {"request_fee", c.RequestFee != 0},
		{"custom_model", c.CustomModel}, {"user_model", c.UserModel}, {"tool_cost", c.ToolCost}, {"search_cost", c.SearchCost},
		{"image_cost", c.ImageCost}, {"video_cost", c.VideoCost}, {"partner", c.Partner}, {"liberty", c.Liberty}, {"native_batch", c.NativeBatch},
		{"fusion", c.Fusion}, {"polyphemus", c.Polyphemus}, {"private_tier_basis", c.PrivateTierBasis},
	} {
		if f.excluded {
			return failure(f.name)
		}
	}
	return nil
}
func (s Snapshot) candidate(endpoint string) (Candidate, error) {
	if s.data == nil {
		return Candidate{}, failure("invalid_snapshot")
	}
	for _, c := range s.data.Candidates {
		if c.EndpointID == endpoint {
			return c, nil
		}
	}
	return Candidate{}, failure("unsupported_endpoint")
}

// Evaluate prices the selected endpoint, normalizing cache exactly once. It
// never consults reservation estimates or clamps charges. Reasoning is a subset
// of output, not an additional component. No request path invokes this function.
func Evaluate(s Snapshot, selectedEndpoint string, raw RawUsage, observed Eligibility) (Evaluation, error) {
	if err := RequireEligible(observed); err != nil {
		return Evaluation{}, err
	}
	c, err := s.candidate(selectedEndpoint)
	if err != nil {
		return Evaluation{}, err
	}
	if err = validateGo(raw, "invalid_usage"); err != nil {
		return Evaluation{}, err
	}
	cached, err := checkedAdd(raw.CacheReadTokens, raw.CacheCreationTokens)
	if err != nil {
		return Evaluation{}, err
	}
	uncached, total := raw.InputTokens, raw.InputTokens
	if c.PromptConvention == "includes_cache" {
		if cached > raw.InputTokens {
			return Evaluation{}, failure("malformed_usage")
		}
		uncached -= cached
	} else {
		total, err = checkedAdd(uncached, cached)
		if err != nil {
			return Evaluation{}, err
		}
	}
	usage := NormalizedUsage{UncachedInputTokens: uncached, TotalPromptTokens: total, OutputTokens: raw.OutputTokens, CacheReadTokens: raw.CacheReadTokens, CacheCreationTokens: raw.CacheCreationTokens, ReasoningTokens: raw.ReasoningTokens}
	if err = validateSemantics(usage); err != nil {
		return Evaluation{}, err
	}
	rates := c.Rates
	if len(c.Tiers) > 0 {
		rates = c.Tiers[len(c.Tiers)-1].Rates
		for _, tier := range c.Tiers {
			if tier.MaxPromptTokens == nil || total <= *tier.MaxPromptTokens {
				rates = tier.Rates
				break
			}
		}
	}
	components := [][2]int64{{uncached, rates.InputMicroPerMillion}, {raw.CacheReadTokens, rates.CachedInputMicroPerMillion}, {raw.CacheCreationTokens, rates.CacheCreationMicroPerMillion}, {raw.OutputTokens, rates.OutputMicroPerMillion}}
	cost := c.RequestFeeMicro
	positive := cost > 0
	for _, component := range components {
		tokens, rate := component[0], component[1]
		product, e := checkedMultiply(tokens, rate)
		if e != nil {
			return Evaluation{}, e
		}
		numerator, e := checkedAdd(product, 500_000)
		if e != nil {
			return Evaluation{}, e
		}
		cost, e = checkedAdd(cost, numerator/1_000_000)
		if e != nil {
			return Evaluation{}, e
		}
		positive = positive || (tokens > 0 && rate > 0)
	}
	if positive && cost == 0 {
		cost = 1
	}
	return Evaluation{Usage: usage, ChargeMicro: cost}, nil
}

// ValidateEnvelope checks the snapshot hash, selected endpoint, normalized usage
// and exact charge. Ticket authentication and authorization identity are outside
// this pure contract. Refunds still validate usage but carry zero charge.
func ValidateEnvelope(s Snapshot, envelope TerminalEnvelope) error {
	return validateEnvelope(s, envelope, Evaluate)
}

// The evaluator argument permits the fixture's explicit boundary fault without
// package globals or a mutable production hook.
func validateEnvelope(s Snapshot, e TerminalEnvelope, evaluate func(Snapshot, string, RawUsage, Eligibility) (Evaluation, error)) error {
	if err := validateGo(e, "invalid_envelope"); err != nil {
		return err
	}
	hash, err := CanonicalHash(s)
	if err != nil {
		return err
	}
	if e.SnapshotHash != hash {
		return failure("snapshot_hash_mismatch")
	}
	c, err := s.candidate(e.SelectedEndpoint)
	if err != nil {
		return err
	}
	u := e.Usage
	input := u.UncachedInputTokens
	if c.PromptConvention == "includes_cache" {
		input = u.TotalPromptTokens
	}
	raw := RawUsage{InputTokens: input, OutputTokens: u.OutputTokens, CacheReadTokens: u.CacheReadTokens, CacheCreationTokens: u.CacheCreationTokens, ReasoningTokens: u.ReasoningTokens}
	observed := DefaultEligibility()
	observed.RouteType = e.RouteType
	observed.Streamed = e.Streamed
	result, err := evaluate(s, e.SelectedEndpoint, raw, observed)
	if err != nil {
		return err
	}
	expected := result.ChargeMicro
	if e.TerminalKind == "refund" {
		expected = 0
	}
	if e.ChargeMicro != expected || e.Usage != result.Usage {
		return failure("charge_mismatch")
	}
	return nil
}
