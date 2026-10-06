package adapter

import (
	"encoding/json"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestLegacyUsageCompatibilityOnBothEndpoints(t *testing.T) {
	for _, value := range []string{`null`, `{}`, `{"include":true}`, `{"include":false}`, `{"include":null}`} {
		t.Run(value, func(t *testing.T) {
			raw := rawChatRequest(t, `{"usage":`+value+`}`)
			result, err := ValidateChatRequestFields(raw)
			if err != nil || len(result.RequestedParameters) != 0 {
				t.Fatalf("legacy usage is local-only, got %#v, %v", result, err)
			}
			if result.IncludeUsage != (value == `{"include":true}`) {
				t.Fatalf("incorrect stream usage selection for %s", value)
			}
			if err := RejectUnsupportedResponsesFields(raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyUsageRejectsMalformedAndUnknownOptions(t *testing.T) {
	for _, tc := range []struct{ value, parameter string }{
		{`true`, "usage"}, {`false`, "usage"}, {`[]`, "usage"}, {`"yes"`, "usage"}, {`1`, "usage"},
		{`{"include":"true"}`, "usage.include"}, {`{"include":0}`, "usage.include"},
		{`{"include":[]}`, "usage.include"}, {`{"include":{}}`, "usage.include"},
		{`{"future":true}`, "usage.future"}, {`{"future":null}`, "usage.future"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			raw := rawChatRequest(t, `{"usage":`+tc.value+`}`)
			_, err := ValidateChatRequestFields(raw)
			assertRequestFieldError(t, err, 400, tc.parameter)
			assertRequestFieldError(t, RejectUnsupportedResponsesFields(raw), 400, tc.parameter)
		})
	}
}

func TestChatCacheRetentionIsRecognizedButNeverSilentlyIgnored(t *testing.T) {
	for _, value := range []string{`"in_memory"`, `"24h"`, `""`, `false`, `{}`} {
		raw := map[string]json.RawMessage{"prompt_cache_retention": json.RawMessage(value)}
		_, err := ValidateChatRequestFields(raw)
		assertRequestFieldError(t, err, 501, "prompt_cache_retention")
		assertRequestFieldError(t, RejectUnsupportedResponsesFields(raw), 501, "prompt_cache_retention")
	}
	result, err := ValidateChatRequestFields(rawChatRequest(t, `{"prompt_cache_retention":null}`))
	if err != nil || len(result.RequestedParameters) != 0 {
		t.Fatalf("null retention should be absent: %#v, %v", result, err)
	}
}

func TestAllPublicRequestFieldsHaveSafeDiagnosticCategories(t *testing.T) {
	for _, fields := range []map[string]struct{}{chatRequestFields, supportedResponsesCreateFields, supportedResponsesInputTokenFields} {
		for field := range fields {
			if got := trustedrouter.ContractParameterCategory(field); got != field {
				t.Errorf("public field %q loses diagnosis as %q", field, got)
			}
		}
	}
}
