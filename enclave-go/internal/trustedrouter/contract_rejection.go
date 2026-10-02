package trustedrouter

import (
	"context"
	"regexp"
	"strings"
)

type contractRejectionContextKey struct{}

type contractRejection struct {
	Status         int    `json:"status"`
	Parameter      string `json:"parameter"`
	RequestID      string `json:"request_id"`
	ParameterPath  string `json:"parameter_path,omitempty"`
	ValuePreview   string `json:"value_preview,omitempty"`
	ValueTruncated bool   `json:"value_truncated,omitempty"`
}

// These are public diagnostic categories, not a request acceptance allowlist.
// Categories bound alert cardinality; separately retained paths contain names only.
// Mirror changes in quill-router/services/gateway_contract_warnings.py first.
var contractParameterCategories = map[string]struct{}{
	"store": {}, "model": {}, "models": {}, "messages": {}, "input": {},
	"instructions": {}, "tools": {}, "tool_choice": {}, "parallel_tool_calls": {},
	"stream": {}, "stream_options": {}, "text": {}, "response_format": {},
	"temperature": {}, "top_p": {}, "reasoning": {}, "reasoning_effort": {},
	"provider": {}, "metadata": {}, "tags": {}, "max_tokens": {},
	"max_output_tokens": {}, "max_completion_tokens": {}, "max_tool_calls": {},
	"previous_response_id": {}, "conversation": {}, "background": {}, "include": {},
	"modalities": {}, "prompt_cache_retention": {}, "usage": {}, "other": {},
	"allow_fallbacks":                   {},
	"cache_control":                     {},
	"debug":                             {},
	"depth":                             {},
	"frequency_penalty":                 {},
	"image_config":                      {},
	"logit_bias":                        {},
	"logprobs":                          {},
	"min_p":                             {},
	"n":                                 {},
	"plugins":                           {},
	"polyphemus":                        {},
	"prediction":                        {},
	"presence_penalty":                  {},
	"prompt":                            {},
	"prompt_cache_key":                  {},
	"prompt_cache_options":              {},
	"repetition_penalty":                {},
	"route":                             {},
	"safety_identifier":                 {},
	"seed":                              {},
	"service_tier":                      {},
	"session_id":                        {},
	"stop":                              {},
	"stop_server_tools_when":            {},
	"top_a":                             {},
	"top_k":                             {},
	"top_logprobs":                      {},
	"trace":                             {},
	"truncation":                        {},
	"user":                              {},
	"web_search_options":                {},
	"usage.include":                     {},
	"stream_options.include_usage":      {},
	"provider.allow_fallbacks":          {},
	"provider.data_collection":          {},
	"provider.enforce_distillable_text": {},
	"provider.ignore":                   {},
	"provider.max_price":                {},
	"provider.only":                     {},
	"provider.order":                    {},
	"provider.preferred_max_latency":    {},
	"provider.preferred_min_throughput": {},
	"provider.quantizations":            {},
	"provider.require_parameters":       {},
	"provider.sort":                     {},
	"provider.sort.by":                  {},
	"provider.sort.partition":           {},
	"provider.zdr":                      {},
	"provider.billing":                  {},
	"provider.min_privacy":              {},
	"provider.options":                  {},
	"provider.usage":                    {},
	"provider.usage_type":               {},
	"provider.max_price.prompt":         {},
	"provider.max_price.completion":     {},
	"provider.max_price.image":          {},
	"provider.max_price.audio":          {},
	"provider.max_price.request":        {},
	"plugins.auto-beta-router":          {},
	"plugins.auto-router":               {},
	"plugins.context-compression":       {},
	"plugins.file-parser":               {},
	"plugins.moderation":                {},
	"plugins.pareto-router":             {},
	"plugins.response-healing":          {},
	"plugins.web-fetch":                 {},
}

// WithContractRejection annotates the existing post-response identity lookup.
// It exports no body or error message. Only sanitized configuration previews
// are exported. Field paths are bounded and
// validated separately, never used as an unbounded Sentry fingerprint.
func WithContractRejection(ctx context.Context, status int, parameter, preview string, truncated bool) context.Context {
	if status != 400 && status != 422 && status != 501 {
		return ctx
	}
	requestID := requestLogIDFromContext(ctx)
	if requestID == "" {
		return ctx
	}
	preview, trimmed := SanitizeContractParameterValue(parameter, preview)
	return context.WithValue(ctx, contractRejectionContextKey{}, contractRejection{
		Status: status, Parameter: ContractParameterCategory(parameter), RequestID: requestID,
		ParameterPath: ContractParameterPath(parameter),
		ValuePreview:  preview, ValueTruncated: preview != "" && (truncated || trimmed),
	})
}

var contractParameterPathPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[[0-9]{1,6}\])?(\.[A-Za-z_][A-Za-z0-9_]*(\[[0-9]{1,6}\])?){0,7}$`)

// ContractParameterPath retains conventional unknown JSON field paths for
// diagnosis. Names over 100 bytes are dropped, never truncated. Free-form
// names, credential-like strings and values are excluded.
func ContractParameterPath(parameter string) string {
	parameter = strings.TrimSpace(parameter)
	parameter, _, _ = strings.Cut(parameter, "=")
	if len(parameter) > 100 {
		return ""
	}
	if _, known := contractParameterCategories[parameter]; known {
		return parameter
	}
	if !contractParameterPathPattern.MatchString(parameter) {
		return ""
	}
	for _, segment := range strings.Split(strings.ToLower(parameter), ".") {
		for _, prefix := range []string{"sk_", "rk_", "pk_", "key_", "ghp_", "github_pat_"} {
			if strings.HasPrefix(segment, prefix) {
				return ""
			}
		}
	}
	return parameter
}

// ContractParameterCategory bounds both logs and the control-plane envelope.
func ContractParameterCategory(parameter string) string {
	parameter = strings.TrimSpace(parameter)
	if _, known := contractParameterCategories[parameter]; known {
		return parameter
	}
	if end := strings.IndexAny(parameter, ".[="); end >= 0 {
		parameter = parameter[:end]
	}
	if _, known := contractParameterCategories[parameter]; !known {
		return "other"
	}
	return parameter
}

func addContractRejection(ctx context.Context, body map[string]any, route string) {
	if route != "/v1/chat/completions" && route != "/v1/responses" {
		return
	}
	if rejection, ok := ctx.Value(contractRejectionContextKey{}).(contractRejection); ok {
		body["contract_rejection"] = rejection
	}
}
