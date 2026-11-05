package upstreamerror

import "strconv"

// Diagnostic emits only status numbers and exact allowlisted symbols, never
// provider messages, raw bodies, or arbitrary code/parameter values.
func Diagnostic(err error) string {
	if err == nil {
		return ""
	}
	status, _, ok := responseBody(err)
	if !ok || status < 400 || status >= 600 {
		return ""
	}
	result := "http=" + strconv.Itoa(status)
	detail := Parse(err)
	if code, ok := detail.Code.(string); ok {
		switch code {
		case "invalid_request_error", "invalid_request", "invalid_api_key",
			"authentication_error", "permission_denied", "model_not_found",
			"model_not_supported", "unsupported_parameter", "unsupported_value",
			"invalid_value", "context_length_exceeded", "rate_limit_exceeded",
			"insufficient_quota", "prepaid_credit_exhausted", "overloaded_error",
			"ValidationException", "AccessDeniedException", "ResourceNotFoundException",
			"ThrottlingException", "ServiceQuotaExceededException", "ModelTimeoutException",
			"ModelNotReadyException", "ServiceUnavailableException", "InternalServerException":
			result += ";code=" + code
		}
	}
	if param, ok := detail.Param.(string); ok {
		switch param {
		case "model", "messages", "input", "tools", "tool_choice", "parallel_tool_calls",
			"reasoning", "reasoning_effort", "include_reasoning", "temperature", "top_p",
			"max_tokens", "max_completion_tokens", "max_output_tokens", "response_format",
			"stream", "stream_options", "stop", "seed", "frequency_penalty",
			"presence_penalty", "repetition_penalty", "logprobs", "top_logprobs",
			"service_tier", "prompt_cache_key", "prompt_cache_retention", "store", "include":
			result += ";param=" + param
		}
	}
	return result
}
