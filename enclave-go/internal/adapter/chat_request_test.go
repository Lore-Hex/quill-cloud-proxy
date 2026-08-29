package adapter

import (
	"encoding/json"
	"testing"
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
			name:    "web search options",
			body:    `{"model":"test/model","messages":[{"role":"user","content":"hi"}],"web_search_options":{"search_context_size":"high"}}`,
			context: "web_search_options",
		},
		{
			name:    "web plugin",
			body:    `{"model":"test/model","messages":[{"role":"user","content":"hi"}],"plugins":[{"id":"web"}]}`,
			context: "plugins.web",
		},
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
