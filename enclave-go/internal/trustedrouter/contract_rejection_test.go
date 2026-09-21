package trustedrouter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestContractRejectionSanitizesAtEnclaveBoundary(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"store", "store"},
		{"store=true", "store"},
		{"tools.private-customer-value", "tools"},
		{"input[123].private-customer-value", "input"},
		{"private-customer-value", "other"},
		{"sk-tr-v1-private-credential", "other"},
		{"alice@example.com", "other"},
		{"", "other"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			ctx := WithRequestLogID(t.Context(), "rlog_"+strings.Repeat("a", 32))
			ctx = WithContractRejection(ctx, 400, tc.input)
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
		ctx = WithContractRejection(ctx, tc.status, "store")
		body := map[string]any{}
		addContractRejection(ctx, body, tc.route)
		if _, exists := body["contract_rejection"]; exists != tc.report {
			t.Fatalf("case %#v: report=%v", tc, exists)
		}
	}
}
