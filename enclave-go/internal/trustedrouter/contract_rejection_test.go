package trustedrouter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRejectedParameterPathsRetainedWithoutValues(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"future_option", "future_option"},
		{"usage.future_option", "usage.future_option"},
		{"input[12].future_option", "input[12].future_option"},
		{"plugins.web-fetch", "plugins.web-fetch"},
		{"store=true", "store"},
		{"alice@example.com", ""}, {"sk-tr-v1-secret", ""},
		{"private customer text", ""}, {"sk_private_secret", ""},
		{strings.Repeat("a", 100), strings.Repeat("a", 100)},
		{"usage." + strings.Repeat("a", 94), "usage." + strings.Repeat("a", 94)},
		{strings.Repeat("a", 101), ""},
		{"usage." + strings.Repeat("a", 95), ""},
		{strings.Repeat("a", 128), ""},
		{strings.Repeat("a", 129), ""}, {"x\nsecret", ""},
		{strings.Repeat("private_prompt_", 100), ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			ctx := WithRequestLogID(t.Context(), "rlog_"+strings.Repeat("a", 32))
			ctx = WithContractRejection(ctx, 400, tc.input, "", false)
			body := map[string]any{}
			addContractRejection(ctx, body, "/v1/chat/completions")
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]map[string]any
			if err := json.Unmarshal(encoded, &payload); err != nil {
				t.Fatal(err)
			}
			got, _ := payload["contract_rejection"]["parameter_path"].(string)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if len(got) > 100 || payload["contract_rejection"]["request_id"] != "rlog_"+strings.Repeat("a", 32) || payload["contract_rejection"]["status"] != float64(400) {
				t.Fatalf("lost safe context or exceeded path limit: %s", encoded)
			}
		})
	}
}

func TestContractRejectionSanitizesAtEnclaveBoundary(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"store", "store"},
		{"store=true", "store"},
		{"plugins", "plugins"},
		{"truncation", "truncation"},
		{"prompt_cache_key", "prompt_cache_key"},
		{"prompt_cache_options", "prompt_cache_options"},
		{"usage.include", "usage.include"},
		{"stream_options.include_usage", "stream_options.include_usage"},
		{"provider.quantizations", "provider.quantizations"},
		{"provider.max_price.image", "provider.max_price.image"},
		{"plugins.web-fetch", "plugins.web-fetch"},
		{"plugins.private-customer-value", "plugins"},
		{"usage.include=private-customer-value", "usage"},
		{"usage.include.private-customer-value", "usage"},
		{"tools.private-customer-value", "tools"},
		{"input[123].private-customer-value", "input"},
		{"private-customer-value", "other"},
		{"sk-tr-v1-private-credential", "other"},
		{"alice@example.com", "other"},
		{"", "other"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			ctx := WithRequestLogID(t.Context(), "rlog_"+strings.Repeat("a", 32))
			ctx = WithContractRejection(ctx, 400, tc.input, "", false)
			body := map[string]any{}
			addContractRejection(ctx, body, "/v1/chat/completions")
			got, ok := body["contract_rejection"].(contractRejection)
			if !ok || got.Parameter != tc.want || got.Status != 400 || got.RequestID == "" {
				t.Fatalf("invalid rejection: %#v", body)
			}
			raw, err := json.Marshal(body)
			if err != nil || strings.Contains(string(raw), "private-") || strings.Contains(string(raw), "alice@") {
				t.Fatalf("content escaped enclave: %s (error %v)", raw, err)
			}
		})
	}
}

func TestContractRejectionRequiresTrustedRouteStatusAndRequestID(t *testing.T) {
	for _, tc := range []struct {
		id, route string
		status    int
		report    bool
	}{
		{"rlog_" + strings.Repeat("a", 32), "/v1/responses", 501, true},
		{"rlog_" + strings.Repeat("a", 32), "/v1/chat/completions", 422, true},
		{"", "/v1/chat/completions", 400, false},
		{"private-customer-value", "/v1/chat/completions", 400, false},
		{"rlog_" + strings.Repeat("a", 32), "/v1/private-customer-value", 400, false},
		{"rlog_" + strings.Repeat("a", 32), "/v1/chat/completions", 401, false},
		{"rlog_" + strings.Repeat("a", 32), "/v1/chat/completions", 402, false},
		{"rlog_" + strings.Repeat("a", 32), "/v1/chat/completions", 429, false},
		{"rlog_" + strings.Repeat("a", 32), "/v1/chat/completions", 500, false},
		{"rlog_" + strings.Repeat("a", 32), "/v1/chat/completions", 200, false},
	} {
		ctx := WithRequestLogID(t.Context(), tc.id)
		ctx = WithContractRejection(ctx, tc.status, "store", "", false)
		body := map[string]any{}
		addContractRejection(ctx, body, tc.route)
		if _, exists := body["contract_rejection"]; exists != tc.report {
			t.Fatalf("case %#v: report=%v", tc, exists)
		}
	}
}
