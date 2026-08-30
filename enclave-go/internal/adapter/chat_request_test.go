package adapter

import (
	"encoding/json"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func rawChatRequest(t *testing.T, body string) map[string]json.RawMessage {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	return raw
}

func TestValidateChatRequestRejectsUnknownTopLevelField(t *testing.T) {
	_, err := ValidateChatRequestFields(rawChatRequest(t, `{
		"model":"test/model",
		"messages":[{"role":"user","content":"hi"}],
		"future_router_option":true
	}`))
	assertRequestFieldError(t, err, 400, "future_router_option")
}

func TestValidateChatRequestRejectsUnknownProviderField(t *testing.T) {
	_, err := ValidateChatRequestFields(rawChatRequest(t, `{
		"model":"test/model",
		"messages":[{"role":"user","content":"hi"}],
		"provider":{"future_router_option":true}
	}`))
	assertRequestFieldError(t, err, 400, "provider.future_router_option")
}

func TestValidateChatRequestNeverSilentlyIgnoresUnsupportedOpenRouterFeatures(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		context string
	}{
		{
			name:    "response healing plugin",
			body:    `{"model":"test/model","messages":[{"role":"user","content":"hi"}],"plugins":[{"id":"response-healing"}]}`,
			context: "plugins.response-healing",
		},
		{
			name:    "provider quantization filter",
			body:    `{"model":"test/model","messages":[{"role":"user","content":"hi"}],"provider":{"quantizations":["fp8"]}}`,
			context: "provider.quantizations",
		},
		{
			name:    "non-token max price",
			body:    `{"model":"test/model","messages":[{"role":"user","content":"hi"}],"provider":{"max_price":{"image":"0.01"}}}`,
			context: "provider.max_price.image",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateChatRequestFields(rawChatRequest(t, tc.body))
			assertRequestFieldError(t, err, 501, tc.context)
		})
	}
}

func TestConfigureChatWebSearchSupportsCurrentOpenRouterTool(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Tools: []any{map[string]any{
			"type": "openrouter:web_search",
			"parameters": map[string]any{
				"engine": "exa", "mode": "fast", "max_results": float64(7),
				"max_uses": float64(2), "search_context_size": "high",
				"allowed_domains": []any{"gov.uk"},
			},
		}},
	}
	if err := ConfigureChatWebSearch(req); err != nil {
		t.Fatal(err)
	}
	if req.Response == nil || req.Response.WebSearch == nil {
		t.Fatal("web search config missing")
	}
	config := req.Response.WebSearch
	if config.RouteType != "chat.completions.web_search" || config.Engine != "exa" || config.Mode != "fast" ||
		config.MaxResults != 7 || config.MaxCalls != 2 || config.SearchContextSize != "high" ||
		len(config.AllowedDomains) != 1 || config.AllowedDomains[0] != "gov.uk" {
		t.Fatalf("config = %#v", config)
	}
	if len(req.Tools) != 1 {
		t.Fatalf("tools = %#v", req.Tools)
	}
	tool := req.Tools[0].(map[string]any)
	function := tool["function"].(map[string]any)
	if tool["type"] != "function" || function["name"] != TrustedRouterWebSearchFunction {
		t.Fatalf("normalized tool = %#v", tool)
	}
}

func TestConfigureChatWebSearchDefaultsToOpenRouterToolCallBudget(t *testing.T) {
	req := &types.OpenAIChatRequest{Tools: []any{map[string]any{"type": "openrouter:web_search"}}}
	if err := ConfigureChatWebSearch(req); err != nil {
		t.Fatal(err)
	}
	if got := req.Response.WebSearch.MaxCalls; got != 30 {
		t.Fatalf("default max calls = %d, want 30", got)
	}
}

func TestConfigureChatWebSearchSupportsLegacyWebPluginAndOptions(t *testing.T) {
	req := &types.OpenAIChatRequest{
		Plugins: []any{map[string]any{
			"id": "web", "engine": "exa", "max_results": float64(4),
			"include_domains": []any{"example.com"}, "search_prompt": "Prefer primary sources.",
		}},
		WebSearchOptions: map[string]any{"search_context_size": "low"},
	}
	if err := ConfigureChatWebSearch(req); err != nil {
		t.Fatal(err)
	}
	config := req.Response.WebSearch
	if config.ToolType != "web_plugin" || !config.ForceSearch || config.MaxCalls != 1 ||
		config.MaxResults != 4 || config.SearchContextSize != "low" || config.SearchPrompt != "Prefer primary sources." {
		t.Fatalf("config = %#v", config)
	}
	choice := req.ToolChoice.(map[string]any)
	if choice["type"] != "function" {
		t.Fatalf("tool choice = %#v", choice)
	}
}

func TestConfigureChatWebSearchRejectsUnknownOrUnsupportedOptions(t *testing.T) {
	for _, test := range []struct {
		name    string
		req     *types.OpenAIChatRequest
		status  int
		context string
	}{
		{
			name: "unknown parameter",
			req: &types.OpenAIChatRequest{Tools: []any{map[string]any{
				"type": "openrouter:web_search", "parameters": map[string]any{"future": true},
			}}},
			status: 400, context: "tools.parameters.future",
		},
		{
			name: "unsupported engine",
			req: &types.OpenAIChatRequest{Tools: []any{map[string]any{
				"type": "openrouter:web_search", "parameters": map[string]any{"engine": "native"},
			}}},
			status: 501, context: "tools.parameters.engine",
		},
		{
			name: "location cannot be a no-op",
			req: &types.OpenAIChatRequest{Tools: []any{map[string]any{
				"type": "openrouter:web_search", "parameters": map[string]any{"user_location": map[string]any{"country": "US"}},
			}}},
			status: 501, context: "tools.parameters.user_location",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ConfigureChatWebSearch(test.req)
			assertRequestFieldError(t, err, test.status, test.context)
		})
	}
}

func TestValidateChatRequestRejectsUnknownMaxPriceField(t *testing.T) {
	_, err := ValidateChatRequestFields(rawChatRequest(t, `{
		"model":"test/model",
		"messages":[{"role":"user","content":"hi"}],
		"provider":{"max_price":{"future_unit":"1.00"}}
	}`))
	assertRequestFieldError(t, err, 400, "provider.max_price.future_unit")
}

func TestValidateChatRequestValidatesProviderSortConfig(t *testing.T) {
	for _, tc := range []struct {
		body        string
		wantStatus  int
		wantContext string
	}{
		{`{"model":"m","messages":[{"role":"user","content":"hi"}],"provider":{"sort":"exacto"}}`, 501, "provider.sort"},
		{`{"model":"m","messages":[{"role":"user","content":"hi"}],"provider":{"sort":{"by":"price","partition":"future"}}}`, 400, "provider.sort.partition"},
		{`{"model":"m","messages":[{"role":"user","content":"hi"}],"provider":{"sort":{"by":"price","future":true}}}`, 400, "provider.sort.future"},
	} {
		_, err := ValidateChatRequestFields(rawChatRequest(t, tc.body))
		assertRequestFieldError(t, err, tc.wantStatus, tc.wantContext)
	}

	_, err := ValidateChatRequestFields(rawChatRequest(t, `{
		"model":"m","messages":[{"role":"user","content":"hi"}],
		"provider":{"sort":{"by":"price","partition":"none"}}
	}`))
	if err != nil {
		t.Fatalf("supported provider.sort object rejected: %v", err)
	}
}

func TestValidateChatRequestRejectsUnknownNestedStreamOption(t *testing.T) {
	_, err := ValidateChatRequestFields(rawChatRequest(t, `{
		"model":"m","messages":[{"role":"user","content":"hi"}],
		"stream_options":{"include_usage":true,"future_option":true}
	}`))
	assertRequestFieldError(t, err, 400, "stream_options.future_option")
}

func TestValidateChatRequestAcceptsSupportedFusionAndDisabledPlugins(t *testing.T) {
	result, err := ValidateChatRequestFields(rawChatRequest(t, `{
		"model":"trustedrouter/synth",
		"messages":[{"role":"user","content":"hi"}],
		"temperature":0.2,
		"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],
		"plugins":[
			{"id":"fusion","analysis_models":["a","b"]},
			{"id":"web","enabled":false}
		],
		"provider":{"zdr":true,"max_price":{"prompt":"1.25","completion":"3.50"}}
	}`))
	if err != nil {
		t.Fatalf("supported request rejected: %v", err)
	}
	for _, want := range []string{"temperature", "tools"} {
		if !containsString(result.RequestedParameters, want) {
			t.Fatalf("requested parameters = %#v, missing %q", result.RequestedParameters, want)
		}
	}
}

func assertRequestFieldError(t *testing.T, err error, status int, context string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected status %d error for %s", status, context)
	}
	aerr, ok := err.(*AdapterError)
	if !ok {
		t.Fatalf("error type = %T, want *AdapterError", err)
	}
	if aerr.Status != status || aerr.Context != context {
		t.Fatalf("error = status %d context %q, want status %d context %q", aerr.Status, aerr.Context, status, context)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
