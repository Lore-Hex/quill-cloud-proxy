package adapter

import (
	"encoding/json"
	"sort"
	"strings"
)

// Normalize known provider spellings into the existing cross-provider control.
// Never forward an unchecked native object or silently choose between controls.
//
// A switch (thinking.type, enable_thinking, or a chat_template_kwargs switch)
// and reasoning_effort are different controls: one turns thinking on or off,
// the other sets its depth. DeepSeek and Z.ai document sending both, so they
// compose into one reasoning object. Off governs: a disabled switch drops the
// effort. Still refused: thinking beside another switch, boolean switches that
// disagree, two depths, and On with an effort that means Off.
func validateThinkingAlias(raw map[string]json.RawMessage) (map[string]any, error) {
	provided := func(key string) bool {
		return len(raw[key]) != 0 && strings.TrimSpace(string(raw[key])) != "null"
	}
	template, err := chatTemplateThinkingSwitch(raw["chat_template_kwargs"])
	if err != nil {
		return nil, err
	}
	field := "thinking"
	if !provided(field) {
		field = "enable_thinking"
	}
	if !provided(field) {
		field = "chat_template_kwargs"
		if template == nil {
			return nil, nil
		}
	}
	bad := func(message string) (map[string]any, error) {
		return nil, &AdapterError{Status: 400, Message: message, Context: field}
	}
	if presentNonNull(raw["reasoning"]) ||
		(field == "thinking" && (provided("enable_thinking") || template != nil)) {
		return bad("specify only one of thinking, enable_thinking, chat_template_kwargs, or reasoning")
	}
	effort := ""
	if provided("reasoning_effort") {
		if err := json.Unmarshal(raw["reasoning_effort"], &effort); err != nil {
			return nil, &AdapterError{Status: 400, Message: "reasoning_effort must be a string", Context: "reasoning_effort"}
		}
	}
	// A blank effort names no depth, as when the field is omitted.
	hasEffort := strings.TrimSpace(effort) != ""
	compose := func(result map[string]any) (map[string]any, error) {
		if result["enabled"] != true || !hasEffort {
			return result, nil
		}
		if ReasoningEffortOff(effort) {
			return bad("reasoning_effort turns reasoning off but " + field + " turns it on")
		}
		result["effort"] = effort
		return result, nil
	}
	if field != "thinking" {
		enabled := template
		if field == "enable_thinking" {
			var value bool
			if err := json.Unmarshal(raw[field], &value); err != nil {
				return bad("enable_thinking must be a boolean")
			}
			if template != nil && *template != value {
				return nil, &AdapterError{Status: 400, Message: "chat_template_kwargs and enable_thinking must agree", Context: "chat_template_kwargs"}
			}
			enabled = &value
		}
		return compose(map[string]any{"enabled": *enabled})
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
	if err := json.Unmarshal(fields["type"], &mode); err != nil || (mode != "enabled" && mode != "disabled" && mode != "adaptive") {
		return bad("thinking.type must be enabled, disabled, or adaptive")
	}
	if mode == "adaptive" && !presentNonNull(raw["output_config"]) && !hasEffort {
		return bad("adaptive thinking requires output_config.effort or reasoning_effort; alternatively use reasoning.effort")
	}
	result := map[string]any{"enabled": mode != "disabled"}
	if value, exists := fields["budget_tokens"]; exists {
		var budget *int
		if err := json.Unmarshal(value, &budget); err != nil || budget == nil || *budget <= 0 || mode != "enabled" {
			return bad("thinking.budget_tokens must be a positive integer with thinking enabled")
		}
		if hasEffort {
			return bad("specify only one of thinking.budget_tokens or reasoning_effort")
		}
		// Match encoding/json's representation of the canonical reasoning object.
		result["max_tokens"] = float64(*budget)
	}
	return compose(result)
}

// ReasoningEffortOff reports an effort that asks for no reasoning. The
// documented word is none. Fireworks and the Claude mapping read the other
// spellings the same way, so none of them can ride along with On.
func ReasoningEffortOff(effort string) bool {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "none", "off", "disable", "disabled":
		return true
	}
	return false
}

// chatTemplateThinkingSwitch reads the thinking switch that vLLM and SGLang
// style servers take in chat_template_kwargs: enable_thinking for Qwen
// templates, thinking for DeepSeek and GLM ones. It is nil when the object
// carries no switch. The object itself is never forwarded, so any other key
// is refused by name, never accepted and dropped.
func chatTemplateThinkingSwitch(value json.RawMessage) (*bool, error) {
	if len(value) == 0 || isJSONNull(value) {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(value, &fields); err != nil {
		return nil, &AdapterError{Status: 400, Message: "chat_template_kwargs must be an object", Context: "chat_template_kwargs"}
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	// Name the same unknown key every time a request carries several.
	sort.Strings(keys)
	for _, key := range keys {
		if key != "enable_thinking" && key != "thinking" {
			return nil, unknownRequestParameter("chat_template_kwargs." + key)
		}
	}
	var enabled *bool
	for _, key := range keys {
		if isJSONNull(fields[key]) {
			continue
		}
		var value bool
		if err := json.Unmarshal(fields[key], &value); err != nil {
			return nil, &AdapterError{Status: 400, Message: "chat_template_kwargs." + key + " must be a boolean", Context: "chat_template_kwargs." + key}
		}
		if enabled != nil && *enabled != value {
			return nil, &AdapterError{Status: 400, Message: "chat_template_kwargs.enable_thinking and chat_template_kwargs.thinking must agree", Context: "chat_template_kwargs"}
		}
		enabled = &value
	}
	return enabled, nil
}
