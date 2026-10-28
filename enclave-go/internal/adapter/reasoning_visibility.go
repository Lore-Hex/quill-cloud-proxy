package adapter

import (
	"bytes"
	"encoding/json"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// The modern exclude setting takes precedence over the legacy include alias.
// Neither setting changes the model's thinking budget or billable usage.
func validateReasoningVisibility(raw map[string]json.RawMessage) (bool, error) {
	exclude := false
	if value := raw["include_reasoning"]; reasoningFlagPresent(value) {
		var include bool
		if err := json.Unmarshal(value, &include); err != nil {
			return false, &AdapterError{Status: 400, Message: "include_reasoning must be a boolean", Context: "include_reasoning"}
		}
		exclude = !include
	}
	var reasoning map[string]json.RawMessage
	if json.Unmarshal(raw["reasoning"], &reasoning) == nil {
		if value := reasoning["exclude"]; reasoningFlagPresent(value) {
			if err := json.Unmarshal(value, &exclude); err != nil {
				return false, &AdapterError{Status: 400, Message: "reasoning.exclude must be a boolean", Context: "reasoning.exclude"}
			}
		}
	}
	return exclude, nil
}

func reasoningFlagPresent(value json.RawMessage) bool {
	value = bytes.TrimSpace(value)
	return len(value) > 0 && !bytes.Equal(value, []byte("null"))
}

func reasoningVisibilityOnly(value json.RawMessage) bool {
	var reasoning map[string]json.RawMessage
	if json.Unmarshal(value, &reasoning) != nil || len(reasoning) == 0 {
		return false
	}
	for key := range reasoning {
		if key != "exclude" {
			return false
		}
	}
	return true
}

// ConfigureReasoningVisibility consumes router-owned output policy before any
// provider request is built. Copy the map so shared subrequests are unchanged.
func ConfigureReasoningVisibility(req *types.OpenAIChatRequest, exclude bool) {
	req.ExcludeReasoning = exclude
	reasoning, ok := req.Reasoning.(map[string]any)
	if !ok {
		return
	}
	if _, exists := reasoning["exclude"]; !exists {
		return
	}
	remaining := make(map[string]any, len(reasoning))
	for key, value := range reasoning {
		if key != "exclude" {
			remaining[key] = value
		}
	}
	req.Reasoning = nil
	if len(remaining) > 0 {
		req.Reasoning = remaining
	}
}

func VisibleThinking(req *types.OpenAIChatRequest, thinking []ThinkingBlock) string {
	if req != nil && req.ExcludeReasoning {
		return ""
	}
	return JoinThinking(thinking)
}

func WithReasoningVisibility(control *StreamControl, exclude bool) *StreamControl {
	if !exclude {
		return control
	}
	copy := StreamControl{}
	if control != nil {
		copy = *control
	}
	copy.ExcludeReasoning = true
	return &copy
}
