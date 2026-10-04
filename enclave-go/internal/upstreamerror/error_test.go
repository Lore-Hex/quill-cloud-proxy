package upstreamerror

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name, body, message, typ string
		code, param              any
		parsed                   bool
	}{
		{"openai", `{"error":{"message":"Refused by policy","type":"content_policy_error","code":"content_filter","param":"messages"}}`, "Refused by policy", "content_policy_error", "content_filter", "messages", true},
		{"anthropic", `{"type":"error","error":{"type":"invalid_request_error","message":"Prompt rejected"}}`, "Prompt rejected", "invalid_request_error", nil, nil, true},
		{"google", `{"error":{"code":400,"message":"Safety policy","status":"INVALID_ARGUMENT"}}`, "Safety policy", "INVALID_ARGUMENT", json.Number("400"), nil, true},
		{"bare", `{"code":400,"msg":"bad request"}`, "bad request", "provider_error", json.Number("400"), nil, true},
		{"message", `{"message":"Rejected"}`, "Rejected", "provider_error", nil, nil, true},
		{"detail", `{"detail":"Rejected"}`, "Rejected", "provider_error", nil, nil, true},
		{"error string", `{"error":"Rejected"}`, "Rejected", "provider_error", nil, nil, true},
		{"plain", "upstream refused", "upstream refused", "provider_error", nil, nil, false},
		{"empty", "", "provider error", "provider_error", nil, nil, false},
		{"empty message", `{"message":"  "}`, `{"message":"  "}`, "provider_error", nil, nil, false},
		{"embedded http", `{"message":"bad http 503: reason"}`, "bad http 503: reason", "provider_error", nil, nil, true},
		{"oversize", `{"error":{"message":"` + strings.Repeat("x", 1500) + `","type":"content_policy_error","code":"refusal"}}`, strings.Repeat("x", 1200), "content_policy_error", "refusal", nil, true},
		{"unicode", strings.Repeat("€", 401), strings.Repeat("€", 400), "provider_error", nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, err := range []error{&Error{Status: 400, Body: tc.body}, fmt.Errorf("wrapped: http 400: %s", tc.body)} {
				want := Detail{Status: 400, Message: tc.message, Type: tc.typ, Code: tc.code, Param: tc.param, Raw: bounded(tc.body), Parsed: tc.parsed}
				if got := Parse(err); !reflect.DeepEqual(got, want) {
					t.Fatalf("got %#v; want %#v", got, want)
				}
			}
		})
	}
	for _, err := range []error{nil, errors.New("transport failed"), errors.New("http 200: nope"), &Error{Status: 999, Body: "bad"}} {
		if got := Parse(err); !reflect.DeepEqual(got, Detail{Status: 502, Message: "provider error", Type: "provider_error"}) {
			t.Fatalf("unclassified: %#v", got)
		}
	}
}

func TestParseRedactsEveryPublicFieldBeforeTruncation(t *testing.T) {
	body := `{"error":{"message":"Bearer SECRET sk-abcdef rk-abcdef","type":"sk-type-secret","code":"sk-code-secret","param":"sk-param-secret"},"api_key":"credential","authorization":"Bearer credential"}`
	want := Detail{Status: 403, Message: "Bearer *** sk-*** sk-***", Type: "sk-***", Code: "sk-***", Param: "sk-***", Raw: `{"api_key":"***","authorization":"***","error":{"code":"sk-***","message":"Bearer *** sk-*** sk-***","param":"sk-***","type":"sk-***"}}`, Parsed: true}
	if got := Parse(&Error{Status: 403, Body: body}); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

func TestFromEvent(t *testing.T) {
	for _, tc := range []struct {
		body    string
		status  int
		message string
	}{
		{`{"error":{"message":"refused","code":400}}`, 400, "refused"},
		{`{"type":"error","error":{"type":"rate_limit_error","message":"limited"}}`, 429, "limited"},
		{`{"error":{"message":"unknown"}}`, 502, "unknown"},
		{`{"type":"response.failed","response":{"error":{"code":"policy","message":"refused"}}}`, 502, "refused"},
		{`{"type":"error","message":"refused","code":403}`, 403, "refused"},
	} {
		err := FromEvent(tc.body)
		if err == nil {
			t.Fatalf("no error: %s", tc.body)
		}
		got := Parse(err)
		if got.Status != tc.status || got.Message != tc.message || got.Raw != tc.body {
			t.Fatalf("got %#v", got)
		}
	}
	for _, body := range []string{`{"error":null}`, `{"choices":[]}`, `malformed`} {
		if err := FromEvent(body); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseRedactsEscapedCredentials(t *testing.T) {
	got := Parse(&Error{Status: 400, Body: `{"error":{"message":"Bearer S\u0045CRET sk-abc\u0064ef"},"api_key":"escaped\"secret"}`})
	want := Detail{Status: 400, Message: "Bearer *** sk-***", Type: "provider_error", Raw: `{"api_key":"***","error":{"message":"Bearer *** sk-***"}}`, Parsed: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}
