package llm

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
)

func TestHixtubeZeroOutputUsageRequiresExplicitCountAndCompleteStream(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		finish, done bool
		wantZero     bool
	}{
		{"explicit_zero", `,"completion_tokens":0`, true, true, true},
		{"missing_output", "", true, true, false},
		{"null_output", `,"completion_tokens":null`, true, true, false},
		{"negative_output", `,"completion_tokens":-1`, true, true, false},
		{"negative_output_with_total", `,"completion_tokens":-1,"total_tokens":1000`, true, true, false},
		{"missing_done", `,"completion_tokens":0`, true, false, false},
		{"missing_finish", `,"completion_tokens":0`, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstream strings.Builder
			if tc.finish {
				upstream.WriteString("data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
			}
			upstream.WriteString(`data: {"choices":[],"usage":{"prompt_tokens":1000,"prompt_tokens_details":{"cached_tokens":900}` + tc.output + "}}\n\n")
			if tc.done {
				upstream.WriteString("data: [DONE]\n\n")
			}
			var normalized bytes.Buffer
			if err := translateOpenAIStreamToAnthropicForProvider(strings.NewReader(upstream.String()), &normalized, "hixtube"); err != nil {
				t.Fatal(err)
			}
			result, err := adapter.CollectAnthropicText(strings.NewReader(normalized.String()))
			if err != nil || result.Usage == nil {
				t.Fatalf("capture: usage=%#v err=%v", result.Usage, err)
			}
			if result.Usage.InputTokens != 1000 || result.Usage.CacheReadInputTokens != 900 || result.Usage.ZeroOutputReported != tc.wantZero {
				t.Fatalf("usage=%#v, want total=1000 cached=900 confirmedZero=%v", result.Usage, tc.wantZero)
			}
		})
	}
}

func TestOpenAIUsageOutputPresenceDoesNotChangeOtherCounts(t *testing.T) {
	for _, tc := range []struct {
		body    string
		count   int
		present bool
	}{
		{`{"prompt_tokens":1000,"completion_tokens":0,"total_tokens":1000,"prompt_tokens_details":{"cached_tokens":900}}`, 0, true},
		{`{"prompt_tokens":1000,"completion_tokens":12,"total_tokens":1012,"prompt_tokens_details":{"cached_tokens":900}}`, 12, true},
		{`{"prompt_tokens":1000,"prompt_tokens_details":{"cached_tokens":900}}`, 0, false},
		{`{"prompt_tokens":1000,"completion_tokens":null,"prompt_tokens_details":{"cached_tokens":900}}`, 0, false},
	} {
		var usage openAIStreamUsage
		if err := json.Unmarshal([]byte(tc.body), &usage); err != nil {
			t.Fatal(err)
		}
		if usage.PromptTokens != 1000 || usage.cachedTokens() != 900 || usage.CompletionTokens != tc.count || usage.CompletionTokensReported != tc.present {
			t.Fatalf("decoded=%#v", usage)
		}
	}
}
