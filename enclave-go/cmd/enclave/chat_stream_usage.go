package main

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// Add only aggregate billing metadata, never private route configuration or
// content. Missing settlement is unreported, not a fabricated zero charge.
func annotateChatTerminalUsage(terminal adapter.StreamTerminal, settlement *trustedrouter.SettleResult, usage trustedrouter.Usage) {
	if settlement == nil || terminal.UsageFields == nil {
		return
	}
	terminal.UsageFields["cost_microdollars"] = settlement.CostMicrodollars
	terminal.UsageFields["total_cost_microdollars"] = settlement.CostMicrodollars
	terminal.UsageFields["prompt_tokens"] = usage.InputTokens
	terminal.UsageFields["completion_tokens"] = usage.OutputTokens
	terminal.UsageFields["total_tokens"] = usage.InputTokens + usage.OutputTokens
	terminal.UsageFields["usage_estimated"] = usage.UsageEstimated
}
