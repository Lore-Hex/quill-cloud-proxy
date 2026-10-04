package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// reportedSettlement fills only reporting metadata. The original settlement
// and the usage sent to billing are never changed. CandidateCostReporting is
// an affirmative control-plane assertion that settlement uses these prices
// without further adjustments. Eligible requests bill the authorization-time
// snapshot; older control planes omit this promise.
func reportedSettlement(settlement *trustedrouter.SettleResult, auth *trustedrouter.Authorization, usage trustedrouter.Usage, settleErr error) *trustedrouter.SettleResult {
	if settlement.HasCost() {
		local := candidateSettlement(nil, auth, usage, nil)
		if local.HasCost() && local.CostMicrodollars != settlement.CostMicrodollars {
			fmt.Fprintf(os.Stderr, "enclave.usage_cost_mismatch level=error authorization_id=%q endpoint_id=%q local_cost_microdollars=%d settled_cost_microdollars=%d\n", auth.AuthorizationID, usage.SelectedEndpoint, local.CostMicrodollars, settlement.CostMicrodollars)
		}
		return settlement
	}
	return candidateSettlement(settlement, auth, usage, settleErr)
}

func candidateSettlement(settlement *trustedrouter.SettleResult, auth *trustedrouter.Authorization, usage trustedrouter.Usage, settleErr error) *trustedrouter.SettleResult {
	var rejected *trustedrouter.ControlPlaneError
	if errors.As(settleErr, &rejected) && rejected.StatusCode >= 400 && rejected.StatusCode < 500 && rejected.StatusCode != 408 && rejected.StatusCode != 429 {
		return settlement
	}
	if auth == nil || !auth.StageD.Eligible || !auth.CandidateCostReporting {
		return settlement
	}
	// A durable intent freezes its own usage as well as its price. A retry's
	// final usage can differ from the preserved intent, so a missing intent
	// price cannot be reconstructed from this attempt even at immutable rates.
	if settlement != nil && settlement.Disposition == trustedrouter.DispositionIntentDurable {
		return settlement
	}
	// A terminal/refunded/reaped authorization can be charged on a different
	// usage snapshot. A missing cost in that response cannot be reconstructed.
	if settlement != nil && (settlement.AlreadySettled || settlement.Settled ||
		(settlement.Disposition != "" && settlement.Disposition != trustedrouter.DispositionIntentDurable) ||
		(settlement.FinalizationOutcome != "" && settlement.FinalizationOutcome != "pending")) {
		return settlement
	}
	if usage.FinishReason == "heartbeat_lost" || usage.AdditionalCostMicrodollars != 0 {
		return settlement
	}
	switch usage.RouteType {
	case "chat.completions", "responses", "messages":
	default:
		return settlement
	}
	// Use the endpoint that actually served, including authorized fallbacks.
	// Never guess the first candidate when the selected endpoint is missing.
	if usage.SelectedEndpoint == "" {
		return settlement
	}
	provider, model, usageType := "", "", ""
	if usage.SelectedEndpoint == auth.EndpointID {
		provider, model, usageType = auth.Provider, auth.Model, auth.UsageType
	}
	for _, candidate := range auth.RouteCandidates {
		if candidate.EndpointID == usage.SelectedEndpoint {
			provider, model, usageType = candidate.Provider, candidate.Model, candidate.UsageType
			break
		}
	}
	if provider == "" || model != usage.SelectedModel || !strings.EqualFold(usageType, "Credits") {
		return settlement
	}
	// An absent candidate has no supported version/rounding and is rejected
	// by CostMicrodollars along with other unusable prices.
	price, _ := auth.CandidatePrice(usage.SelectedEndpoint)
	input := usage.InputTokens
	if input < 0 {
		return settlement
	}
	// Match normalized_prompt_accounting: only Anthropic's prompt count is
	// exclusive of cache reads/writes. Other providers include the cache.
	if provider != "anthropic" {
		input -= min(input, usage.CacheReadInputTokens)
		input -= min(input, usage.CacheCreationInputTokens)
	}
	tierInput := 0
	if provider == "sakana" && model == "sakana-ai/fugu-ultra-v1.1" {
		tierInput = usage.PriceTierInputTokens
	}
	cost, ok := price.CostMicrodollars(input, usage.OutputTokens, usage.CacheReadInputTokens, usage.CacheCreationInputTokens, tierInput)
	if !ok {
		return settlement
	}
	reported := trustedrouter.SettleResult{}
	if settlement != nil {
		reported = *settlement
	}
	reported.CostMicrodollars = cost
	reported.CostMicrodollarsKnown = true
	return &reported
}

func annotateUsageCost(usage map[string]any, settlement *trustedrouter.SettleResult) {
	// Native Messages relays provider usage. Its optional price fields are not
	// evidence of the customer's TrustedRouter charge.
	delete(usage, "cost_microdollars")
	delete(usage, "total_cost_microdollars")
	if usage == nil || !settlement.HasCost() {
		return
	}
	usage["cost_microdollars"] = settlement.CostMicrodollars
	usage["total_cost_microdollars"] = settlement.CostMicrodollars
}
