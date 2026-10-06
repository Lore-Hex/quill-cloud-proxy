package trustedrouter

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
)

// Mirror this positive configuration-only policy at the control-plane sink.
// Unknown fields may contain prompts or credentials, even when short.
var contractValueOptions = strings.Fields(`
	temperature top_p top_k top_a min_p max_tokens max_output_tokens
	max_completion_tokens max_tool_calls n seed depth frequency_penalty
	presence_penalty repetition_penalty logprobs top_logprobs stream store
	allow_fallbacks parallel_tool_calls background usage.include
	stream_options.include_usage reasoning.enabled reasoning.exclude reasoning.max_tokens
	provider.allow_fallbacks provider.require_parameters provider.zdr
	provider.max_price.prompt provider.max_price.completion provider.max_price.image
	provider.max_price.audio provider.max_price.request
`)

var contractValueEnums = map[string]string{
	"prompt_cache_retention":   "in_memory 24h",
	"prompt_cache_options.ttl": "in_memory 24h",
	"reasoning_effort":         "none minimal low medium high xhigh max auto",
	"reasoning.effort":         "none minimal low medium high xhigh max auto",
	"service_tier":             "auto default flex priority scale",
	"truncation":               "auto disabled",
	"provider.data_collection": "allow deny",
	"provider.min_privacy":     "standard zdr confidential",
	"provider.usage":           "byok prepaid credits",
	"provider.billing":         "byok prepaid credits",
	"response_format.type":     "text json_object json_schema",
	"text.format.type":         "text json_object json_schema",
}

// These are diagnostic option names, not an API capability allowlist. Never
// treat arbitrary strings or nested payloads as safe just because they fit.
var contractValueArrayEnums = map[string]string{
	"include": `code_interpreter_call.outputs computer_call_output.output.image_url
		file_search_call.results message.input_image.image_url message.output_text.logprobs
		reasoning.encrypted_content web_search_call.action.sources web_search_call.results`,
	"modalities": "text audio image video",
}

// ContractParameterValue extracts only the rejected option, not the surrounding
// request. Redaction precedes the 100-byte budget. Oversized collections lose
// trailing entries but remain valid JSON so the sink can validate them again.
func ContractParameterValue(body []byte, parameter string) (string, bool) {
	path := ContractParameterPath(parameter)
	if path == "" {
		return "", false
	}
	raw := json.RawMessage(body)
	// A literal dotted unknown key is rejected at the top level before nested
	// validation. Do not accidentally report a different nested option's value.
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return "", false
	}
	if exact, ok := top[path]; ok {
		raw = exact
	} else {
		for _, part := range strings.Split(path, ".") {
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil {
				return "", false
			}
			var ok bool
			raw, ok = fields[part]
			if !ok {
				return "", false
			}
		}
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return boundedContractValue(safeContractValue(path, value))
}

// Revalidate an already bounded preview at each export boundary.
func SanitizeContractParameterValue(parameter, preview string) (string, bool) {
	path := ContractParameterPath(parameter)
	if path == "" || preview == "" || len(preview) > 100 {
		return "", false
	}
	var value any
	if json.Unmarshal([]byte(preview), &value) != nil {
		return "", false
	}
	return boundedContractValue(safeContractValue(path, value))
}

func contractValuePolicy(path string) (bool, []string) {
	for _, option := range contractValueOptions {
		if option == path {
			return true, strings.Fields("true false yes no on off enabled disabled auto none")
		}
	}
	if values, ok := contractValueEnums[path]; ok {
		return true, strings.Fields(values)
	}
	if values, ok := contractValueArrayEnums[path]; ok {
		return true, strings.Fields(values)
	}
	return false, nil
}

func contractValueChildren(path string) []string {
	children := map[string]bool{}
	add := func(option string) {
		if tail, ok := strings.CutPrefix(option, path+"."); ok {
			child, _, _ := strings.Cut(tail, ".")
			children[child] = true
		}
	}
	for _, option := range contractValueOptions {
		add(option)
	}
	for option := range contractValueEnums {
		add(option)
	}
	result := make([]string, 0, len(children))
	for child := range children {
		result = append(result, child)
	}
	sort.Strings(result)
	return result
}

func safeContractValue(path string, value any) any {
	allowed, enums := contractValuePolicy(path)
	switch value := value.(type) {
	case nil:
		return nil
	case bool:
		if allowed {
			return value
		}
		return "[redacted:boolean]"
	case float64:
		if allowed && !math.IsNaN(value) && !math.IsInf(value, 0) && math.Abs(value) <= 1e12 {
			return value
		}
		return "[redacted:number]"
	case string:
		for _, marker := range strings.Fields("[redacted:string] [redacted:number] [redacted:boolean] [redacted:object] [redacted:array]") {
			if value == marker {
				return marker
			}
		}
		for _, enum := range enums {
			if value == enum {
				return value
			}
		}
		return "[redacted:string]"
	case map[string]any:
		children := contractValueChildren(path)
		if len(children) == 0 {
			return "[redacted:object]"
		}
		out := map[string]any{}
		for _, child := range children {
			if field, ok := value[child]; ok {
				out[child] = safeContractValue(path+"."+child, field)
			}
		}
		if len(out) < len(value) {
			out["_redacted"] = true
		}
		return out
	case []any:
		if _, ok := contractValueArrayEnums[path]; !ok {
			return "[redacted:array]"
		}
		// Even the smallest JSON elements cannot fit 101 entries in 100 bytes.
		// Bound sanitizer work; the budget pass will mark this prefix truncated.
		out := make([]any, 0, min(len(value), 101))
		for _, item := range value[:min(len(value), 101)] {
			if _, nested := item.([]any); nested {
				out = append(out, "[redacted:array]")
			} else {
				out = append(out, safeContractValue(path, item))
			}
		}
		return out
	default:
		return "[redacted:array]"
	}
}

func boundedContractValue(value any) (string, bool) {
	truncated := false
	for {
		encoded, err := json.Marshal(value)
		if err != nil {
			return "", false
		}
		if len(encoded) <= 100 {
			return string(encoded), truncated
		}
		if array, ok := value.([]any); ok && len(array) > 0 {
			value = array[:len(array)-1]
			truncated = true
			continue
		}
		object, ok := value.(map[string]any)
		if !ok || len(object) == 0 {
			return "", false
		}
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		delete(object, keys[len(keys)-1])
		truncated = true
	}
}
