package adapter

import "testing"

// This compact fixture was extracted from https://openrouter.ai/openapi.json
// on 2026-08-29. Updating it is deliberate: a new OpenRouter option must be
// classified as supported or explicitly unsupported before it can ship.
func TestOpenRouterRequestContractCoverage(t *testing.T) {
	chatFields := []string{
		"cache_control", "debug", "frequency_penalty", "image_config", "logit_bias",
		"logprobs", "max_completion_tokens", "max_tokens", "max_tool_calls", "messages", "metadata",
		"min_p", "modalities", "model", "models", "parallel_tool_calls", "plugins",
		"prediction", "presence_penalty", "prompt_cache_key", "prompt_cache_options",
		"provider", "reasoning", "reasoning_effort", "repetition_penalty",
		"response_format", "route", "seed", "service_tier", "session_id", "stop",
		"stop_server_tools_when", "stream", "stream_options", "temperature",
		"tool_choice", "tools", "top_a", "top_k", "top_logprobs", "top_p", "trace", "user",
		"web_search_options",
	}
	responsesFields := []string{
		"background", "cache_control", "debug", "frequency_penalty", "image_config",
		"include", "input", "instructions", "max_output_tokens", "max_tool_calls",
		"metadata", "modalities", "model", "models", "parallel_tool_calls", "plugins",
		"presence_penalty", "previous_response_id", "prompt", "prompt_cache_key",
		"prompt_cache_options", "provider", "reasoning", "route", "safety_identifier",
		"service_tier", "session_id", "stop_server_tools_when", "store", "stream",
		"temperature", "text", "tool_choice", "tools", "top_k", "top_logprobs",
		"top_p", "trace", "truncation", "user",
	}
	providerFields := []string{
		"allow_fallbacks", "data_collection", "enforce_distillable_text", "ignore",
		"max_price", "only", "order", "preferred_max_latency",
		"preferred_min_throughput", "quantizations", "require_parameters", "sort", "zdr",
	}
	pluginIDs := []string{
		"auto-router", "auto-beta-router", "moderation", "web", "web-fetch",
		"file-parser", "response-healing", "context-compression", "pareto-router", "fusion",
	}

	assertClassified(t, "chat field", chatFields, chatRequestFields)
	assertClassified(t, "responses field", responsesFields, supportedResponsesCreateFields)
	assertClassified(t, "provider field", providerFields, providerRoutingFields)
	for _, id := range pluginIDs {
		_, supported := supportedPluginIDs[id]
		_, unsupported := knownUnsupportedPluginIDs[id]
		if supported == unsupported {
			t.Errorf("plugin %q must be classified exactly once", id)
		}
	}
}

func assertClassified(t *testing.T, kind string, values []string, classified map[string]struct{}) {
	t.Helper()
	for _, value := range values {
		if _, ok := classified[value]; !ok {
			t.Errorf("%s %q is unclassified", kind, value)
		}
	}
}
