package adapter

type ResponsesCoverageItem struct {
	Method string
	Path   string
	Kind   string
}

var ResponsesCoverage = []ResponsesCoverageItem{
	{Method: "POST", Path: "/v1/responses", Kind: "stateless-real"},
	{Method: "POST", Path: "/v1/responses/input_tokens", Kind: "stateless-real"},
	{Method: "GET", Path: "/v1/responses/{response_id}", Kind: "explicit-stub"},
	{Method: "DELETE", Path: "/v1/responses/{response_id}", Kind: "explicit-stub"},
	{Method: "POST", Path: "/v1/responses/{response_id}/cancel", Kind: "explicit-stub"},
	{Method: "POST", Path: "/v1/responses/compact", Kind: "explicit-stub"},
	{Method: "GET", Path: "/v1/responses/{response_id}/input_items", Kind: "explicit-stub"},
	{Method: "POST", Path: "/v1/conversations", Kind: "explicit-stub"},
	{Method: "GET", Path: "/v1/conversations/{conversation_id}", Kind: "explicit-stub"},
	{Method: "PATCH", Path: "/v1/conversations/{conversation_id}", Kind: "explicit-stub"},
	{Method: "DELETE", Path: "/v1/conversations/{conversation_id}", Kind: "explicit-stub"},
	{Method: "POST", Path: "/v1/conversations/{conversation_id}/items", Kind: "explicit-stub"},
	{Method: "GET", Path: "/v1/conversations/{conversation_id}/items", Kind: "explicit-stub"},
	{Method: "GET", Path: "/v1/conversations/{conversation_id}/items/{item_id}", Kind: "explicit-stub"},
	{Method: "DELETE", Path: "/v1/conversations/{conversation_id}/items/{item_id}", Kind: "explicit-stub"},
}

var ResponsesCreateFieldCoverage = []ResponsesCoverageItem{
	{Path: "background", Kind: "explicit-stub"},
	{Path: "conversation", Kind: "explicit-stub"},
	{Path: "include", Kind: "explicit-stub"},
	{Path: "input", Kind: "stateless-real"},
	{Path: "instructions", Kind: "stateless-real"},
	{Path: "max_output_tokens", Kind: "stateless-real"},
	{Path: "max_tokens", Kind: "stateless-real"},
	{Path: "max_tool_calls", Kind: "explicit-stub"},
	{Path: "metadata", Kind: "stateless-real"},
	{Path: "modalities", Kind: "stateless-real"},
	{Path: "model", Kind: "stateless-real"},
	{Path: "models", Kind: "stateless-real"},
	{Path: "parallel_tool_calls", Kind: "stateless-real"},
	{Path: "previous_response_id", Kind: "explicit-stub"},
	{Path: "prompt", Kind: "explicit-stub"},
	{Path: "prompt_cache_key", Kind: "stateless-real"},
	{Path: "prompt_cache_retention", Kind: "explicit-stub"},
	{Path: "provider", Kind: "stateless-real"},
	{Path: "reasoning", Kind: "explicit-stub"},
	{Path: "safety_identifier", Kind: "stateless-real"},
	{Path: "service_tier", Kind: "stateless-real"},
	{Path: "session_id", Kind: "stateless-real"},
	{Path: "store", Kind: "explicit-stub"},
	{Path: "stream", Kind: "stateless-real"},
	{Path: "stream_options", Kind: "stateless-real"},
	{Path: "temperature", Kind: "stateless-real"},
	{Path: "text", Kind: "stateless-real"},
	{Path: "tool_choice", Kind: "explicit-stub"},
	{Path: "tools", Kind: "explicit-stub"},
	{Path: "top_logprobs", Kind: "explicit-stub"},
	{Path: "top_p", Kind: "stateless-real"},
	{Path: "trace", Kind: "stateless-real"},
	{Path: "truncation", Kind: "stateless-real"},
	{Path: "user", Kind: "stateless-real"},
}
