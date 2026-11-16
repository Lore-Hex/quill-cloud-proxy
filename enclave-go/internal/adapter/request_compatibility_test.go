package adapter

import (
	"encoding/json"
	"reflect"
	"strings"
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

func TestResponsesClientMetadataIsAcceptedWithoutEffect(t *testing.T) {
	for _, value := range []string{`null`, `{}`, `{"x-codex-installation-id":"private-value","nested":{"turn":["private-value"]}}`} {
		raw := rawChatRequest(t, `{"model":"m","input":"hi","client_metadata":`+value+`}`)
		if err := RejectUnsupportedResponsesFields(raw); err != nil {
			t.Fatalf("client_metadata %s: %v", value, err)
		}
	}
	for _, value := range []string{`"private-value"`, `["private-value"]`, `[]`, `true`, `7`} {
		body := `{"model":"m","input":"hi","client_metadata":` + value + `}`
		err := RejectUnsupportedResponsesFields(rawChatRequest(t, body))
		assertRequestFieldError(t, err, 400, "client_metadata")
		// A refusal reports the value's type, never the value.
		preview, truncated := trustedrouter.ContractParameterValue([]byte(body), "client_metadata")
		if !strings.HasPrefix(preview, `"[redacted:`) || truncated || strings.Contains(err.Error(), "private-value") {
			t.Fatalf("client_metadata %s: preview=%s error=%v", value, preview, err)
		}
	}
	found := false
	for _, item := range ResponsesCreateFieldCoverage {
		found = found || (item.Path == "client_metadata" && item.Kind == "stateless-real")
	}
	if !found {
		t.Fatal("client_metadata missing from Responses create field coverage")
	}
	// Only Responses create takes it. Token counting accepts the fields that
	// shape the counted input, and chat completions has no such field.
	tokens := rawChatRequest(t, `{"model":"m","input":"hi","client_metadata":{"x-codex-installation-id":"private-value"}}`)
	assertRequestFieldError(t, RejectUnsupportedResponsesInputTokenFields(tokens), 400, "client_metadata")
	_, err := ValidateChatRequestFields(rawChatRequest(t, `{"client_metadata":{}}`))
	assertRequestFieldError(t, err, 400, "client_metadata")
}

func TestChatTemplateKwargsReportsTheEnableThinkingCapability(t *testing.T) {
	for _, tc := range []struct {
		body string
		want []string
	}{
		{`{"enable_thinking":false}`, []string{"reasoning"}},
		{`{"chat_template_kwargs":{"enable_thinking":false}}`, []string{"reasoning"}},
		{`{"chat_template_kwargs":{"thinking":true}}`, []string{"reasoning"}},
		{`{"chat_template_kwargs":{"thinking":true},"reasoning_effort":"high","temperature":0}`, []string{"reasoning", "temperature"}},
		{`{"chat_template_kwargs":{}}`, []string{}},
		{`{"chat_template_kwargs":{"enable_thinking":null}}`, []string{}},
		{`{"chat_template_kwargs":null}`, []string{}},
	} {
		result, err := ValidateChatRequestFields(rawChatRequest(t, tc.body))
		if err != nil || !reflect.DeepEqual(result.RequestedParameters, tc.want) {
			t.Fatalf("%s: parameters=%v err=%v", tc.body, result.RequestedParameters, err)
		}
	}
	if endpointCapabilityFields["chat_template_kwargs"] != endpointCapabilityFields["enable_thinking"] {
		t.Fatal("chat_template_kwargs must report the capability enable_thinking reports")
	}
	// The control plane and its fast-path edge each hold a fixed list of the
	// requested-parameter names they understand (quill-router's
	// ORDINARY_PARAMETERS). A chat field may only report one of those.
	ordinary := strings.Fields(`temperature top_p max_tokens max_completion_tokens max_output_tokens
		stop seed frequency_penalty presence_penalty logit_bias logprobs top_logprobs response_format
		reasoning_effort stream reasoning tools tool_choice parallel_tool_calls top_k top_a min_p
		repetition_penalty prediction prompt_cache_key service_tier`)
	for field, capability := range endpointCapabilityFields {
		if !containsString(ordinary, capability) {
			t.Errorf("chat field %q reports %q, a name the control plane does not hold", field, capability)
		}
	}
}
