package adapter

import (
	"encoding/json"
	"strings"
)

// Normalize known provider spellings into the existing cross-provider control.
// Never forward an unchecked native object or silently choose between controls.
func validateThinkingAlias(raw map[string]json.RawMessage) (map[string]any, error) {
	provided := func(key string) bool {
		return len(raw[key]) != 0 && strings.TrimSpace(string(raw[key])) != "null"
	}
	field := "thinking"
	if !provided(field) {
		field = "enable_thinking"
	}
	if !provided(field) {
		return nil, nil
	}
	bad := func(message string) (map[string]any, error) {
		return nil, &AdapterError{Status: 400, Message: message, Context: field}
	}
	if presentNonNull(raw["reasoning"]) || presentNonNull(raw["reasoning_effort"]) ||
		(field == "thinking" && provided("enable_thinking")) {
		return bad("specify only one of thinking, enable_thinking, reasoning, or reasoning_effort")
	}
	if field == "enable_thinking" {
		var enabled bool
		if err := json.Unmarshal(raw[field], &enabled); err != nil {
			return bad("enable_thinking must be a boolean")
		}
		return map[string]any{"enabled": enabled}, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw[field], &fields); err != nil {
		return bad("thinking must be an object")
	}
	for key := range fields {
		if key != "type" && key != "budget_tokens" {
			return nil, unknownRequestParameter("thinking." + key)
		}
	}
	var mode string
	if err := json.Unmarshal(fields["type"], &mode); err != nil || (mode != "enabled" && mode != "disabled") {
		return bad("thinking.type must be enabled or disabled; use reasoning for other controls")
	}
	result := map[string]any{"enabled": mode == "enabled"}
	if value, exists := fields["budget_tokens"]; exists {
		var budget *int
		if err := json.Unmarshal(value, &budget); err != nil || budget == nil || *budget <= 0 || mode != "enabled" {
			return bad("thinking.budget_tokens must be a positive integer with thinking enabled")
		}
		// Match encoding/json's representation of the canonical reasoning object.
		result["max_tokens"] = float64(*budget)
	}
	return result, nil
}
