package adapter

import (
	"bytes"
	"encoding/json"
)

// Legacy usage.include controls the local stream usage chunk, never routing
// or billing. Non-streaming and Responses usage is always returned.
func validateLegacyUsage(value json.RawMessage) (bool, error) {
	if len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return false, nil
	}
	var options map[string]json.RawMessage
	if err := json.Unmarshal(value, &options); err != nil {
		return false, &AdapterError{Status: 400, Message: "usage must be an object", Context: "usage"}
	}
	for key := range options {
		if key != "include" {
			return false, unknownRequestParameter("usage." + key)
		}
	}
	if include, ok := options["include"]; ok {
		var enabled *bool
		if err := json.Unmarshal(include, &enabled); err != nil {
			return false, &AdapterError{Status: 400, Message: "usage.include must be a boolean", Context: "usage.include"}
		}
		return enabled != nil && *enabled, nil
	}
	return false, nil
}

// A provider-specific retention policy must not be accepted and dropped or
// inferred from store=false. No supported route can yet guarantee this control.
func rejectPromptCacheRetention(value json.RawMessage) error {
	if len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil
	}
	return unsupportedRequestParameter("prompt_cache_retention")
}
