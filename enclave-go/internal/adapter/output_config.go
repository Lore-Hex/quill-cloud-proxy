package adapter

import "encoding/json"

// Chat accepts the native effort spelling, but normalizes it before routing so
// fallback and every Claude transport use the same validated reasoning control.
// Native /v1/messages keeps its separate, unmodified output_config passthrough.
func validateOutputConfigAlias(raw map[string]json.RawMessage, thinking map[string]any) (map[string]any, error) {
	if !reasoningFlagPresent(raw["output_config"]) {
		return thinking, nil
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(raw["output_config"], &config); err != nil {
		return nil, &AdapterError{Status: 400, Message: "output_config must be an object", Context: "output_config"}
	}
	for key := range config {
		if key != "effort" {
			return nil, unknownRequestParameter("output_config." + key)
		}
	}
	bad := func(message string) (map[string]any, error) {
		return nil, &AdapterError{Status: 400, Message: message, Context: "output_config.effort"}
	}
	var effort string
	if err := json.Unmarshal(config["effort"], &effort); err != nil {
		return bad("output_config.effort must be low, medium, high, xhigh, or max")
	}
	switch effort {
	case "low", "medium", "high", "xhigh", "max":
	default:
		return bad("output_config.effort must be low, medium, high, xhigh, or max")
	}
	if presentNonNull(raw["reasoning_effort"]) || (presentNonNull(raw["reasoning"]) && !reasoningVisibilityOnly(raw["reasoning"])) {
		return bad("specify only one of output_config.effort, reasoning, or reasoning_effort")
	}
	if enabled, ok := thinking["enabled"].(bool); ok && !enabled {
		return bad("output_config.effort cannot be combined with disabled thinking on chat completions; use /v1/messages for native controls")
	}
	result := map[string]any{"effort": effort}
	for key, value := range thinking {
		result[key] = value
	}
	return result, nil
}
