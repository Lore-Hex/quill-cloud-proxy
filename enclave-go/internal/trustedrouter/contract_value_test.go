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
		{"output_config.effort", `{"output_config":{"effort":"high"}}`, `"high"`},
		{"output_config.effort", `{"output_config":{"effort":"private-content"}}`, `"[redacted:string]"`},
		{"output_config", `{"output_config":{"effort":"high","secret":"private-content"}}`, `{"_redacted":true,"effort":"high"}`},
		{"include", `{"include":["reasoning.encrypted_content"]}`, `["reasoning.encrypted_content"]`},
		{"include", `{"include":["message.output_text.logprobs","web_search_call.action.sources"]}`, `["message.output_text.logprobs","web_search_call.action.sources"]`},
		{"modalities", `{"modalities":["text","audio"]}`, `["text","audio"]`},
		{"include", `{"include":[]}`, `[]`},
		{"include", `{"include":["reasoning.encrypted_content","private-content","sk-private-key"]}`, `["reasoning.encrypted_content","[redacted:string]","[redacted:string]"]`},
		{"include", `{"include":[{"content":"private-content"},["private-content"],null]}`, `["[redacted:object]","[redacted:array]",null]`},
		{"stream", `{"stream":null}`, `null`},
		{"tools[0].type", `{"tools":[{"type":"custom","custom":{"name":"private-content"}}]}`, `"custom"`},
		{"tools[1].type", `{"tools":[{"type":"function"},{"type":"web_search"}]}`, `"web_search"`},
		{"tools[0].type", `{"tools":[{"type":"mcp","server_url":"https://private-content"}]}`, `"mcp"`},
		{"tools[0].type", `{"tools":[{"type":"private-content"}]}`, `"[redacted:string]"`},
		{"tools[0].type", `{"tools":[{"type":{"secret":"private-content"}}]}`, `"[redacted:object]"`},
		{"tools[0].function.name", `{"tools":[{"function":{"name":"private-content"}}]}`, `"[redacted:string]"`},
		{"tools[0].type", `{"tools[0].type":"private-content","tools":[{"type":"custom"}]}`, `"[redacted:string]"`},
		{"tools[3].type", `{"tools":[{"type":"custom"}]}`, ``},
		{"tools[999999].type", `{"tools":[{"type":"custom"}]}`, ``},
		{"tools[0].type", `{"tools":{"type":"custom"}}`, ``},
		{"tools[0].type", `{"tools":[null]}`, ``},
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
		// A refused thinking switch shows its shape, never its other members.
		{"thinking", `{"thinking":{"type":"enabled"}}`, `{"type":"enabled"}`},
		{"thinking", `{"thinking":{"type":"adaptive","budget_tokens":8000}}`, `{"budget_tokens":8000,"type":"adaptive"}`},
		{"thinking", `{"thinking":{"type":"auto","display":"private-content","signature":"sk-private-key"}}`, `{"_redacted":true,"type":"auto"}`},
		{"thinking", `{"thinking":{"type":"private-content","budget_tokens":"private-content"}}`, `{"budget_tokens":"[redacted:string]","type":"[redacted:string]"}`},
		{"thinking", `{"thinking":{"type":{"secret":"private-content"},"budget_tokens":true,"display":"private-content"}}`, `{"_redacted":true,"budget_tokens":true,"type":"[redacted:object]"}`},
		{"thinking", `{"thinking":true}`, `"[redacted:boolean]"`},
		{"thinking", `{"thinking":"private-content"}`, `"[redacted:string]"`},
		{"thinking.type", `{"thinking":{"type":"disabled"}}`, `"disabled"`},
		{"thinking.type", `{"thinking":{"type":"private-content"}}`, `"[redacted:string]"`},
		{"thinking.budget_tokens", `{"thinking":{"budget_tokens":1.5}}`, `1.5`},
		{"thinking.budget_tokens", `{"thinking":{"budget_tokens":"private-content"}}`, `"[redacted:string]"`},
		{"thinking.display", `{"thinking":{"display":"private-content"}}`, `"[redacted:string]"`},
		{"enable_thinking", `{"enable_thinking":false}`, `false`},
		{"enable_thinking", `{"enable_thinking":"false"}`, `"false"`},
		{"enable_thinking", `{"enable_thinking":"private-content"}`, `"[redacted:string]"`},
		{"chat_template_kwargs", `{"chat_template_kwargs":{"enable_thinking":false,"thinking":true}}`, `{"enable_thinking":false,"thinking":true}`},
		{"chat_template_kwargs", `{"chat_template_kwargs":{"enable_thinking":false,"documents":["private-content"],"prompt":"private-content"}}`, `{"_redacted":true,"enable_thinking":false}`},
		{"chat_template_kwargs", `{"chat_template_kwargs":{"enable_thinking":{"secret":"private-content"},"thinking":"private-content","prompt":"x"}}`, `{"_redacted":true,"enable_thinking":"[redacted:object]","thinking":"[redacted:string]"}`},
		{"chat_template_kwargs", `{"chat_template_kwargs":"private-content"}`, `"[redacted:string]"`},
		{"chat_template_kwargs.thinking", `{"chat_template_kwargs":{"thinking":{"type":"private-content"}}}`, `"[redacted:object]"`},
		{"chat_template_kwargs.enable_thinking", `{"chat_template_kwargs":{"enable_thinking":"private-content"}}`, `"[redacted:string]"`},
		{"chat_template_kwargs.documents", `{"chat_template_kwargs":{"documents":"private-content"}}`, `"[redacted:string]"`},
		{"chat_template_kwargs.add_generation_prompt", `{"chat_template_kwargs":{"add_generation_prompt":true}}`, `"[redacted:boolean]"`},
		// client_metadata holds client and installation identifiers: no member
		// of it is configuration, whatever a key is called.
		{"client_metadata", `{"client_metadata":"private-content"}`, `"[redacted:string]"`},
		{"client_metadata", `{"client_metadata":["private-content"]}`, `"[redacted:array]"`},
		{"client_metadata", `{"client_metadata":{"x-codex-installation-id":"private-content","type":"enabled","enable_thinking":true,"temperature":0.7}}`, `"[redacted:object]"`},
		{"client_metadata.type", `{"client_metadata":{"type":"enabled"}}`, `"[redacted:string]"`},
		{"client_metadata.enable_thinking", `{"client_metadata":{"enable_thinking":true}}`, `"[redacted:boolean]"`},
		{"client_metadata.temperature", `{"client_metadata":{"temperature":0.7}}`, `"[redacted:number]"`},
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

func TestContractArrayPreviewBudget(t *testing.T) {
	for _, count := range []int{3, 4, 101, 10000} {
		values := make([]string, count)
		for i := range values {
			values[i] = "reasoning.encrypted_content"
		}
		body, _ := json.Marshal(map[string]any{"include": values, "input": "private-content"})
		preview, truncated := ContractParameterValue(body, "include")
		want := `["reasoning.encrypted_content","reasoning.encrypted_content","reasoning.encrypted_content"]`
		if preview != want || truncated != (count > 3) || len(preview) > 100 || !json.Valid([]byte(preview)) {
			t.Fatalf("count=%d preview=%q truncated=%t", count, preview, truncated)
		}
		ctx := WithRequestLogID(t.Context(), "rlog_"+strings.Repeat("a", 32))
		ctx = WithContractRejection(ctx, 501, "include", preview, truncated)
		wire := map[string]any{}
		addContractRejection(ctx, wire, "/v1/responses")
		got := wire["contract_rejection"].(contractRejection)
		if got.ValuePreview != preview || got.ValueTruncated != truncated {
			t.Fatalf("preview lost at export boundary: %#v", got)
		}
	}
	for _, private := range []string{strings.Repeat("private-content", 10000), "private\ncontent", "秘密内容"} {
		body, _ := json.Marshal(map[string]any{"include": []string{private, "reasoning.encrypted_content"}})
		preview, truncated := ContractParameterValue(body, "include")
		if preview != `["[redacted:string]","reasoning.encrypted_content"]` || truncated {
			t.Fatalf("raw string escaped: %q", preview)
		}
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
