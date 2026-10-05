package trustedrouter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestContractValuePreviewPrivacy(t *testing.T) {
	for _, tc := range []struct{ parameter, body, want string }{
		{"store", `{"store":true}`, `true`},
		{"store=true", `{"store":true}`, `true`},
		{"temperature", `{"temperature":0.7}`, `0.7`},
		{"usage.include", `{"usage":{"include":"false"}}`, `"false"`},
		{"usage.include", `{"usage.include":"private-content","usage":{"include":true}}`, `"[redacted:string]"`},
		{"usage", `{"usage":{"include":true}}`, `{"include":true}`},
		{"usage", `{"usage":{"include":true,"secret":"private-content"}}`, `{"_redacted":true,"include":true}`},
		{"prompt_cache_retention", `{"prompt_cache_retention":"24h"}`, `"24h"`},
		{"reasoning.effort", `{"reasoning":{"effort":"high"}}`, `"high"`},
		{"stream", `{"stream":null}`, `null`},
		{"temperature", `{"temperature":1e200}`, `"[redacted:number]"`},
		{"temperature", `{"temperature":"private-content"}`, `"[redacted:string]"`},
		{"usage.include", `{"usage":{"include":{"secret":"private-content"}}}`, `"[redacted:object]"`},
		{"usage", `{"usage":["private-content"]}`, `"[redacted:array]"`},
		{"future", `{"future":"private-content"}`, `"[redacted:string]"`},
		{"future", `{"future":123456}`, `"[redacted:number]"`},
		{"future", `{"future":true}`, `"[redacted:boolean]"`},
		{"messages", `{"messages":[{"content":"private-content"}]}`, `"[redacted:array]"`},
		{"prompt", `{"prompt":"private-content"}`, `"[redacted:string]"`},
		{"metadata", `{"metadata":{"secret":"private-content"}}`, `"[redacted:object]"`},
		{"api_key", `{"api_key":"sk-tr-v1-private-secret"}`, `"[redacted:string]"`},
		{"model", `{"model":"private-content"}`, `"[redacted:string]"`},
		{"usage.include", `{"usage":true}`, ``},
		{"usage.include", `{"usage":{}}`, ``},
		{"usage", `{`, ``},
	} {
		t.Run(tc.parameter+"/"+tc.body, func(t *testing.T) {
			got, truncated := ContractParameterValue([]byte(tc.body), tc.parameter)
			if got != tc.want || truncated {
				t.Fatalf("preview=%s truncated=%t want=%s", got, truncated, tc.want)
			}
			if got != "" {
				again, _ := SanitizeContractParameterValue(tc.parameter, got)
				if again != got {
					t.Fatalf("preview not stable across export boundaries: %s -> %s", got, again)
				}
			}
		})
	}
}

func TestContractValueBudgetAndNoPromptPrefix(t *testing.T) {
	for _, path := range []string{"temperature", "future", "prompt_cache_retention"} {
		body, _ := json.Marshal(map[string]any{path: strings.Repeat("private_content_", 1000)})
		preview, _ := ContractParameterValue(body, path)
		if strings.Contains(preview, "private") || len(preview) > 100 {
			t.Fatal("prompt prefix escaped")
		}
	}
	body := []byte(`{"provider":{"allow_fallbacks":false,"require_parameters":true,"zdr":true,"data_collection":"deny","min_privacy":"confidential","usage":"credits","billing":"prepaid","max_price":{"prompt":0.1,"completion":0.2}}}`)
	preview, truncated := ContractParameterValue(body, "provider")
	if !truncated || len(preview) > 100 || !json.Valid([]byte(preview)) || !strings.Contains(preview, `"allow_fallbacks":false`) {
		t.Fatalf("invalid bounded preview: %q truncated=%t", preview, truncated)
	}
	ctx := WithRequestLogID(t.Context(), "rlog_"+strings.Repeat("a", 32))
	ctx = WithContractRejection(ctx, 400, "provider", preview, truncated)
	request := map[string]any{}
	addContractRejection(ctx, request, "/v1/chat/completions")
	got := request["contract_rejection"].(contractRejection)
	if !got.ValueTruncated || got.ValuePreview != preview {
		t.Fatalf("lost preview on wire: %#v", got)
	}
	for _, invalid := range []string{strings.Repeat("a", 101), "{", `NaN`} {
		if value, _ := SanitizeContractParameterValue("temperature", invalid); value != "" {
			t.Fatal("accepted invalid preview")
		}
	}
}
