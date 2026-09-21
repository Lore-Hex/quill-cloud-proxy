package trustedrouter

import (
	"context"
	"strings"
)

type contractRejectionContextKey struct{}

type contractRejection struct {
	Status    int    `json:"status"`
	Parameter string `json:"parameter"`
	RequestID string `json:"request_id"`
}

// These are public diagnostic categories, not a request acceptance allowlist.
// Unknown names may themselves contain customer content and never leave the enclave.
var contractParameterCategories = map[string]struct{}{
	"store": {}, "model": {}, "models": {}, "messages": {}, "input": {},
	"instructions": {}, "tools": {}, "tool_choice": {}, "parallel_tool_calls": {},
	"stream": {}, "stream_options": {}, "text": {}, "response_format": {},
	"temperature": {}, "top_p": {}, "reasoning": {}, "reasoning_effort": {},
	"provider": {}, "metadata": {}, "tags": {}, "max_tokens": {},
	"max_output_tokens": {}, "max_completion_tokens": {}, "max_tool_calls": {},
	"previous_response_id": {}, "conversation": {}, "background": {}, "include": {},
	"modalities": {}, "prompt_cache_retention": {}, "usage": {}, "other": {},
}

// WithContractRejection annotates the existing post-response identity lookup.
// It exports no body, field value, error message, or arbitrary parameter name.
func WithContractRejection(ctx context.Context, status int, parameter string) context.Context {
	if status != 400 && status != 422 && status != 501 {
		return ctx
	}
	requestID := requestLogIDFromContext(ctx)
	if requestID == "" {
		return ctx
	}
	return context.WithValue(ctx, contractRejectionContextKey{}, contractRejection{
		Status: status, Parameter: ContractParameterCategory(parameter), RequestID: requestID,
	})
}

// ContractParameterCategory bounds both logs and the control-plane envelope.
func ContractParameterCategory(parameter string) string {
	parameter = strings.TrimSpace(parameter)
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
