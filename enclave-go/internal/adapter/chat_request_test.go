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

func TestConfigureChatWebSearchSupportsResponsesToolAliases(t *testing.T) {
	for _, toolType := range []string{"web_search", "web_search_preview"} {
		t.Run(toolType, func(t *testing.T) {
			tool := map[string]any{
				"type": " " + toolType + " ", "search_context_size": "high",
				"user_location": map[string]any{"type": "approximate", "country": "DE", "city": "Berlin"},
			}
			if toolType == "web_search" {
				tool["filters"] = map[string]any{"allowed_domains": []any{"example.com"}}
			}
			req := &types.OpenAIChatRequest{
				Tools: []any{tool}, ToolChoice: map[string]any{"type": toolType},
			}
			if err := ConfigureChatWebSearch(req); err != nil {
				t.Fatal(err)
			}
			config := req.Response.WebSearch
			if config.ToolType != toolType || config.RouteType != "chat.completions.web_search" ||
				config.Engine != "exa" || config.MaxCalls != 3 || config.SearchContextSize != "high" ||
				config.UserCountry != "DE" || config.UserCity != "Berlin" {
				t.Fatalf("config = %#v", config)
			}
			if toolType == "web_search" && (len(config.AllowedDomains) != 1 || config.AllowedDomains[0] != "example.com") {
				t.Fatalf("filters = %#v", config.AllowedDomains)
			}
			fn := req.Tools[0].(map[string]any)["function"].(map[string]any)
			choice := req.ToolChoice.(map[string]any)
			if fn["name"] != TrustedRouterWebSearchFunction || choice["function"].(map[string]any)["name"] != fn["name"] {
				t.Fatalf("normalized tool=%#v choice=%#v", req.Tools, req.ToolChoice)
			}
		})
	}
}

func TestConfigureChatWebSearchAliasesFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		status    int
		parameter string
	}{
		{"duplicates", `{"tools":[{"type":"openrouter:web_search"},{"type":"web_search"}]}`, 400, "tools"},
		{"mixed plugin", `{"tools":[{"type":"web_search"}],"plugins":[{"id":"web"}]}`, 400, "plugins.web"},
		{"budget", `{"tools":[{"type":"web_search"}],"max_tool_calls":4}`, 400, "max_tool_calls"},
		{"offline", `{"tools":[{"type":"web_search","external_web_access":false}]}`, 501, "tools.external_web_access"},
		{"preview filters", `{"tools":[{"type":"web_search_preview","filters":{"allowed_domains":["example.com"]}}]}`, 501, "tools.filters"},
		{"unknown option", `{"tools":[{"type":"web_search","future_option":true}]}`, 501, "tools.future_option"},
		{"unsupported hosted tool", `{"tools":[{"type":"file_search"}]}`, 501, "tools[0].type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req types.OpenAIChatRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatal(err)
			}
			assertRequestFieldError(t, ConfigureChatWebSearch(&req), tc.status, tc.parameter)
		})
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
