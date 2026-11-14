package main

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// Add only aggregate billing metadata, never private route configuration or
// content. Missing settlement is unreported, not a fabricated zero charge.
func annotateChatTerminalUsage(terminal adapter.StreamTerminal, settlement *trustedrouter.SettleResult, usage trustedrouter.Usage) {
	annotateEstimatedTokenUsage(terminal.UsageFields, usage)
	annotateStreamUsageCost(terminal.UsageFields, settlement)
	if !settlement.HasCost() || terminal.UsageFields == nil {
		return
	}
	terminal.UsageFields["prompt_tokens"] = usage.InputTokens
	terminal.UsageFields["completion_tokens"] = usage.OutputTokens
	terminal.UsageFields["total_tokens"] = usage.InputTokens + usage.OutputTokens
	terminal.UsageFields["usage_estimated"] = usage.UsageEstimated
}

// Decorate existing usage frames at emission time, after winner selection and
// settlement hooks. Do not change usage opt-out, settlement timing, or framing.
func withChatRoutingMetadata(control *adapter.StreamControl, auth *trustedrouter.Authorization, selected *selectedRouteTracker, options []llm.InvokeOptions) *adapter.StreamControl {
	if auth == nil || selected == nil || auth.CustomModel != nil {
		return control
	}
	if control == nil {
		control = &adapter.StreamControl{}
	}
	annotate := func(fields map[string]any) {
		if fields != nil {
			fields["provider_usage"] = pruneEmptyProviderUsage(selectedRouteUsage(auth, nil, selected, options))
		}
	}
	before := control.BeforeTerminal
	control.BeforeTerminal = func(terminal adapter.StreamTerminal) error {
		emit := terminal.Emit
		terminal.Emit = func() error {
			annotate(terminal.UsageFields)
			return emit()
		}
		if before != nil {
			return before(terminal)
		}
		return terminal.Emit()
	}
	if after := control.AfterTerminal; after != nil {
		control.AfterTerminal = func(result adapter.StreamResult) (map[string]any, error) {
			metadata, err := after(result)
			if err == nil {
				fields, _ := metadata["usage"].(map[string]any)
				annotate(fields)
			}
			return metadata, err
		}
	}
	return control
}
