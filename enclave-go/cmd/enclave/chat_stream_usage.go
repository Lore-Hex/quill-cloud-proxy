package main

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// Add only aggregate billing metadata, never private route configuration or
// content. Missing settlement is unreported, not a fabricated zero charge.
func annotateChatTerminalUsage(terminal adapter.StreamTerminal, settlement *trustedrouter.SettleResult, usage trustedrouter.Usage) {
	annotateEstimatedTokenUsage(terminal.UsageFields, usage)
	if !settlement.HasCost() || terminal.UsageFields == nil {
		return
	}
	annotateUsageCost(terminal.UsageFields, settlement)
	terminal.UsageFields["prompt_tokens"] = usage.InputTokens
	terminal.UsageFields["completion_tokens"] = usage.OutputTokens
	terminal.UsageFields["total_tokens"] = usage.InputTokens + usage.OutputTokens
	terminal.UsageFields["usage_estimated"] = usage.UsageEstimated
}
