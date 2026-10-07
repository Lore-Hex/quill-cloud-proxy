package main

import (
	"math"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func tokensForSettlement(result adapter.StreamResult, estimatedInput, estimatedOutput int, model string, req *types.OpenAIChatRequest, auth *trustedrouter.Authorization, endpoint string) (int, int, bool) {
	input, output, estimated := realOrEstimatedTokens(result, estimatedInput, estimatedOutput, model)
	input, output = bufferedMissingUsage(result, input, output, model, req, auth, endpoint)
	return input, output, estimated
}

// Only reviewed prepaid Abliterate routes use the disclosed conservative
// estimate. Never infer the provider from a model namespace: fallback and
// BYOK candidates can have different accounting contracts.
func abliterateEstimatedRoute(auth *trustedrouter.Authorization, endpoint, model string) bool {
	if auth == nil || endpoint == "" {
		return false
	}
	switch model {
	case "abliterate/abliterate-0.3-fast", "abliterate/abliterate-0.3-balanced", "abliterate/abliterate-0.3-clever", "abliterate/abliterated-research-0.1":
	default:
		return false
	}
	for _, candidate := range auth.RouteCandidates {
		if candidate.EndpointID == endpoint {
			return candidate.Model == model && candidate.Provider == "abliterate" && candidate.UsageType == "Credits"
		}
	}
	return auth.EndpointID == endpoint && auth.Model == model && auth.Provider == "abliterate" && auth.UsageType == "Credits"
}

func bufferedMissingUsage(result adapter.StreamResult, input, output int, model string, req *types.OpenAIChatRequest, auth *trustedrouter.Authorization, endpoint string) (int, int) {
	if !abliterateEstimatedRoute(auth, endpoint, model) || !auth.CandidateCostReporting || req == nil || input <= 0 || output <= 0 || input > math.MaxInt/2 || output > math.MaxInt/2 || input > math.MaxInt/2-output {
		return input, output
	}
	// Do not buffer incomplete, empty, failed, or partially metered responses.
	if usage := result.Usage; usage != nil && (usage.InputTokens != 0 || usage.OutputTokens != 0 || usage.ReasoningTokens != 0 || usage.CacheReadInputTokens != 0 || usage.CacheCreationInputTokens != 0) {
		return input, output
	}
	if strings.TrimSpace(result.Text) == "" {
		return input, output
	}
	switch result.FinishReason {
	case "stop", "end_turn", "length", "max_tokens":
	default:
		return input, output
	}
	cap := int64(auth.EstimatedCostMicrodollars)
	if auth.CapMicro > 0 && (cap <= 0 || auth.CapMicro < cap) {
		cap = auth.CapMicro
	}
	price, ok := auth.CandidatePrice(endpoint)
	if !ok || cap <= 0 || auth.ReceiptFeeBasisPoints != 0 || auth.CustomModel != nil {
		return input, output
	}
	// This is only a limit on the optional buffer. The control plane remains
	// the billing authority and still enforces the original reservation/cap.
	fits := func(in, out int) bool {
		cost, valid := price.CostMicrodollars(in, out, 0, 0, in)
		return valid && int64(cost) <= cap
	}
	if !fits(input, output) {
		return input, output
	}
	maxOutput := 512
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		maxOutput = *req.MaxTokens
	}
	input = largestBufferedCount(input, input*2, func(n int) bool { return fits(n, output) })
	output = largestBufferedCount(output, min(output*2, maxOutput), func(n int) bool { return fits(input, n) })
	return input, output
}

func largestBufferedCount(base, limit int, fits func(int) bool) int {
	for base < limit {
		mid := base + (limit-base)/2 + 1
		if fits(mid) {
			base = mid
		} else {
			limit = mid - 1
		}
	}
	return base
}

// The client must see the same estimated counts that settlement receives,
// including on native Messages and Responses terminal events.
func annotateEstimatedTokenUsage(fields map[string]any, usage trustedrouter.Usage) {
	if fields == nil {
		return
	}
	fields["usage_estimated"] = usage.UsageEstimated
	if !usage.UsageEstimated {
		return
	}
	if usage.RouteType == "chat.completions" {
		fields["prompt_tokens"], fields["completion_tokens"] = usage.InputTokens, usage.OutputTokens
	} else {
		fields["input_tokens"], fields["output_tokens"] = usage.InputTokens, usage.OutputTokens
	}
	if usage.RouteType != "messages" {
		fields["total_tokens"] = usage.InputTokens + usage.OutputTokens
	}
}
