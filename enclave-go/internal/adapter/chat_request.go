package adapter

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ChatRequestValidation is enclave-owned routing metadata derived from the
// exact request shape. It is not serialized to an upstream model provider.
type ChatRequestValidation struct {
	RequestedParameters []string
}

var chatRequestFields = map[string]struct{}{
	// OpenRouter ChatRequest fields from https://openrouter.ai/openapi.json.
	"cache_control": {}, "debug": {}, "frequency_penalty": {}, "image_config": {},
	"logit_bias": {}, "logprobs": {}, "max_completion_tokens": {}, "max_tokens": {},
	"messages": {}, "metadata": {}, "min_p": {}, "modalities": {}, "model": {},
	"models": {}, "parallel_tool_calls": {}, "plugins": {}, "prediction": {},
	"presence_penalty": {}, "prompt_cache_key": {}, "prompt_cache_options": {},
	"provider": {}, "reasoning": {}, "reasoning_effort": {}, "repetition_penalty": {},
	"response_format": {}, "route": {}, "seed": {}, "service_tier": {}, "session_id": {},
	"stop": {}, "stop_server_tools_when": {}, "stream": {}, "stream_options": {},
	"temperature": {}, "tool_choice": {}, "tools": {}, "top_a": {}, "top_k": {},
	"top_logprobs": {}, "top_p": {}, "trace": {}, "user": {}, "web_search_options": {},
	// TrustedRouter compatibility/extensions already supported by the gateway.
	"allow_fallbacks": {}, "depth": {}, "max_output_tokens": {}, "n": {}, "tags": {},
}

var unsupportedChatFields = map[string]struct{}{
	"cache_control": {}, "debug": {}, "image_config": {}, "route": {},
	"stop_server_tools_when": {}, "web_search_options": {},
}

var providerRoutingFields = map[string]struct{}{
	// Current OpenRouter ProviderPreferences fields.
	"allow_fallbacks": {}, "data_collection": {}, "enforce_distillable_text": {},
	"ignore": {}, "max_price": {}, "only": {}, "order": {},
	"preferred_max_latency": {}, "preferred_min_throughput": {}, "quantizations": {},
	"require_parameters": {}, "sort": {}, "zdr": {},
	// TrustedRouter compatibility fields.
	"billing": {}, "country": {}, "headquarters_country": {}, "jurisdiction": {},
	"min_privacy": {}, "options": {}, "provider_country": {}, "usage": {}, "usage_type": {},
}

var unsupportedProviderRoutingFields = map[string]struct{}{
	"enforce_distillable_text": {}, "options": {}, "preferred_max_latency": {},
	"preferred_min_throughput": {}, "quantizations": {},
}

var supportedPluginIDs = map[string]struct{}{
	"fusion": {}, "map_reduce": {}, "mapreduce": {}, "selector": {}, "synth": {},
}

var knownUnsupportedPluginIDs = map[string]struct{}{
	"auto-beta-router": {}, "auto-router": {}, "context-compression": {},
	"file-parser": {}, "moderation": {}, "pareto-router": {}, "response-healing": {},
	"web": {}, "web-fetch": {},
}

var endpointCapabilityFields = map[string]string{
	"frequency_penalty":     "frequency_penalty",
	"logit_bias":            "logit_bias",
	"logprobs":              "logprobs",
	"max_completion_tokens": "max_tokens",
	"max_output_tokens":     "max_tokens",
	"max_tokens":            "max_tokens",
	"min_p":                 "min_p",
	"parallel_tool_calls":   "parallel_tool_calls",
	"prediction":            "prediction",
	"presence_penalty":      "presence_penalty",
	"prompt_cache_key":      "prompt_cache_key",
	"prompt_cache_options":  "prompt_cache_key",
	"reasoning":             "reasoning",
	"reasoning_effort":      "reasoning",
	"repetition_penalty":    "repetition_penalty",
	"response_format":       "response_format",
	"seed":                  "seed",
	"service_tier":          "service_tier",
	"stop":                  "stop",
	"temperature":           "temperature",
	"tool_choice":           "tool_choice",
	"tools":                 "tools",
	"top_a":                 "top_a",
	"top_k":                 "top_k",
	"top_logprobs":          "top_logprobs",
	"top_p":                 "top_p",
}

// ValidateChatRequestFields makes the OpenRouter compatibility contract
// explicit. Unknown fields are 400s; known fields that this release cannot
// honor are stable 501s. Nothing accepted here may silently disappear.
func ValidateChatRequestFields(raw map[string]json.RawMessage) (ChatRequestValidation, error) {
	requested := make(map[string]struct{})
	for key, value := range raw {
		if _, ok := chatRequestFields[key]; !ok {
			return ChatRequestValidation{}, unknownRequestParameter(key)
		}
		if !presentNonNull(value) {
			continue
		}
		if _, unsupported := unsupportedChatFields[key]; unsupported {
			return ChatRequestValidation{}, unsupportedRequestParameter(key)
		}
		if capability, ok := endpointCapabilityFields[key]; ok {
			requested[capability] = struct{}{}
		}
	}
	if value, ok := raw["modalities"]; ok {
		if err := validateTextModalities(value); err != nil {
			return ChatRequestValidation{}, err
		}
	}
	if value, ok := raw["plugins"]; ok {
		if err := validateChatPlugins(value); err != nil {
			return ChatRequestValidation{}, err
		}
	}
	if value, ok := raw["stream_options"]; ok {
		if err := validateChatStreamOptions(value); err != nil {
			return ChatRequestValidation{}, err
		}
	}
	if value, ok := raw["provider"]; ok {
		if err := validateProviderRouting(value); err != nil {
			return ChatRequestValidation{}, err
		}
	}
	parameters := make([]string, 0, len(requested))
	for parameter := range requested {
		parameters = append(parameters, parameter)
	}
	sort.Strings(parameters)
	return ChatRequestValidation{RequestedParameters: parameters}, nil
}

func validateChatStreamOptions(value json.RawMessage) error {
	if !presentNonNull(value) {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(value, &raw); err != nil {
		return &AdapterError{Status: 400, Message: "stream_options must be an object", Context: "stream_options"}
	}
	for key, field := range raw {
		if key != "include_usage" {
			return unknownRequestParameter("stream_options." + key)
		}
		if presentNonNull(field) {
			var enabled bool
			if err := json.Unmarshal(field, &enabled); err != nil {
				return &AdapterError{Status: 400, Message: "stream_options.include_usage must be a boolean", Context: "stream_options.include_usage"}
			}
		}
	}
	return nil
}

func validateChatPlugins(value json.RawMessage) error {
	if !presentNonNull(value) {
		return nil
	}
	var plugins []map[string]json.RawMessage
	if err := json.Unmarshal(value, &plugins); err != nil {
		return &AdapterError{Status: 400, Message: "plugins must be an array of objects", Context: "plugins"}
	}
	for index, plugin := range plugins {
		var id string
		if rawID, ok := plugin["id"]; ok {
			if err := json.Unmarshal(rawID, &id); err != nil {
				return &AdapterError{Status: 400, Message: "plugin id must be a string", Context: fmt.Sprintf("plugins[%d].id", index)}
			}
		}
		id = strings.TrimSpace(strings.ToLower(id))
		if id == "" {
			return &AdapterError{Status: 400, Message: "plugin id is required", Context: fmt.Sprintf("plugins[%d].id", index)}
		}
		if enabled, ok := plugin["enabled"]; ok && presentNonNull(enabled) {
			var parsed bool
			if err := json.Unmarshal(enabled, &parsed); err != nil {
				return &AdapterError{Status: 400, Message: "plugin enabled must be a boolean", Context: fmt.Sprintf("plugins[%d].enabled", index)}
			}
		}
		if pluginDisabled(plugin) {
			continue
		}
		if _, ok := supportedPluginIDs[id]; ok {
			continue
		}
		if _, ok := knownUnsupportedPluginIDs[id]; ok {
			return unsupportedRequestParameter("plugins." + id)
		}
		return unknownRequestParameter("plugins." + id)
	}
	return nil
}

func pluginDisabled(plugin map[string]json.RawMessage) bool {
	value, ok := plugin["enabled"]
	if !ok {
		return false
	}
	var enabled bool
	return json.Unmarshal(value, &enabled) == nil && !enabled
}

func validateProviderRouting(value json.RawMessage) error {
	if !presentNonNull(value) {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(value, &raw); err != nil {
		return &AdapterError{Status: 400, Message: "provider must be an object", Context: "provider"}
	}
	for key, fieldValue := range raw {
		context := "provider." + key
		if _, ok := providerRoutingFields[key]; !ok {
			return unknownRequestParameter(context)
		}
		if !presentNonNull(fieldValue) {
			continue
		}
		if _, unsupported := unsupportedProviderRoutingFields[key]; unsupported {
			return unsupportedRequestParameter(context)
		}
		if key == "max_price" {
			if err := validateMaxPrice(fieldValue); err != nil {
				return err
			}
		}
		if key == "sort" {
			if err := validateProviderSort(fieldValue); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateProviderSort(value json.RawMessage) error {
	var name string
	if err := json.Unmarshal(value, &name); err == nil {
		return validateProviderSortName(name)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(value, &raw); err != nil {
		return &AdapterError{Status: 400, Message: "provider.sort must be a string or object", Context: "provider.sort"}
	}
	for key := range raw {
		if key != "by" && key != "partition" && key != "sort" && key != "strategy" {
			return unknownRequestParameter("provider.sort." + key)
		}
	}
	for _, key := range []string{"by", "sort", "strategy"} {
		if field, ok := raw[key]; ok && presentNonNull(field) {
			if err := json.Unmarshal(field, &name); err != nil {
				return &AdapterError{Status: 400, Message: "provider.sort.by must be a string", Context: "provider.sort.by"}
			}
			if err := validateProviderSortName(name); err != nil {
				return err
			}
			break
		}
	}
	if field, ok := raw["partition"]; ok && presentNonNull(field) {
		var partition string
		if err := json.Unmarshal(field, &partition); err != nil {
			return &AdapterError{Status: 400, Message: "provider.sort.partition must be a string", Context: "provider.sort.partition"}
		}
		if partition != "model" && partition != "none" {
			return &AdapterError{Status: 400, Message: "provider.sort.partition is unsupported", Context: "provider.sort.partition"}
		}
	}
	return nil
}

func validateProviderSortName(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "price", "throughput", "latency":
		return nil
	case "exacto":
		return unsupportedRequestParameter("provider.sort")
	default:
		return &AdapterError{Status: 400, Message: "provider.sort is unsupported", Context: "provider.sort"}
	}
}

func validateMaxPrice(value json.RawMessage) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(value, &raw); err != nil {
		return &AdapterError{Status: 400, Message: "provider.max_price must be an object", Context: "provider.max_price"}
	}
	for key, fieldValue := range raw {
		context := "provider.max_price." + key
		switch key {
		case "prompt", "completion":
		case "audio", "image", "request":
			if presentNonNull(fieldValue) {
				return unsupportedRequestParameter(context)
			}
		default:
			return unknownRequestParameter(context)
		}
	}
	return nil
}

func unknownRequestParameter(context string) error {
	return &AdapterError{Status: 400, Message: "unknown request parameter", Context: context}
}

func unsupportedRequestParameter(context string) error {
	return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: context}
}
