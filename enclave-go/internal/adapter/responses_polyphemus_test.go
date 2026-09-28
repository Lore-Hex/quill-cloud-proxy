package adapter

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// decodeResponses mirrors the enclave parser: validate raw, decode, then build
// the options from the raw map.
func decodeResponses(body []byte) (*types.OpenAIResponsesRequest, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	if err := RejectUnsupportedResponsesFields(raw); err != nil {
		return nil, err
	}
	var req types.OpenAIResponsesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	options, err := PolyphemusOptionsFromRaw(raw)
	req.Polyphemus = options
	return &req, err
}

func polyphemusResponsesRequest(t *testing.T, body string) (map[string]json.RawMessage, error) {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatal(err)
	}
	return raw, validateResponsesFields(raw, supportedResponsesCreateFields)
}

func TestPolyphemusOptionsParseAndReachTheChatRequest(t *testing.T) {
	body := `{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":"openai/gpt-6-astra","model_zoo":"openai/*"}}`
	if _, err := polyphemusResponsesRequest(t, body); err != nil {
		t.Fatal(err)
	}
	req, err := decodeResponses([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	chat, err := ResponsesToChat(req)
	if err != nil {
		t.Fatal(err)
	}
	if chat.Polyphemus == nil || chat.Polyphemus.XPerf != "openai/gpt-6-astra" || chat.Polyphemus.ModelZoo != "openai/*" {
		t.Fatalf("options lost: %#v", chat.Polyphemus)
	}
	number, _ := decodeResponses([]byte(`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":1}}`))
	if chat, err := ResponsesToChat(number); err != nil || chat.Polyphemus.XPerf != 1.0 {
		t.Fatalf("numeric x_perf: %v %#v", err, chat)
	}
}

func TestPolyphemusOptionsAreRejectedPrecisely(t *testing.T) {
	for _, tc := range []struct{ body, context string }{
		{`{"model":"openai/gpt-6-astra","input":"hi","polyphemus":{"x_perf":1}}`, "polyphemus"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":0.05}}`, "polyphemus.x_perf"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":true}}`, "polyphemus.x_perf"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":"not a model"}}`, "polyphemus.x_perf"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"model_zoo":"openai/*,"}}`, "polyphemus.model_zoo"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"xPerf":1}}`, "polyphemus.xPerf"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":"fast"}`, "polyphemus"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":null}`, "polyphemus"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":null}}`, "polyphemus.x_perf"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"model_zoo":null}}`, "polyphemus.model_zoo"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"model_zoo":{}}}`, "polyphemus.model_zoo"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"model_zoo":7}}`, "polyphemus.model_zoo"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":1e999}}`, "polyphemus.x_perf"},
		{`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":{"a":1}}}`, "polyphemus.x_perf"},
	} {
		_, err := polyphemusResponsesRequest(t, tc.body)
		if err == nil {
			req, parseErr := decodeResponses([]byte(tc.body))
			if parseErr != nil {
				err = parseErr
			} else {
				_, err = ResponsesToChat(req)
			}
		}
		var aerr *AdapterError
		if !errors.As(err, &aerr) || aerr.Status != 400 || aerr.Context != tc.context {
			t.Fatalf("%s: got %v, want 400 on %s", tc.body, err, tc.context)
		}
	}
}

func TestPolyphemusIsRejectedByPresenceWhereUnsupported(t *testing.T) {
	for _, body := range []string{
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{}}`,
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":null}`,
	} {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &raw); err != nil {
			t.Fatal(err)
		}
		err := RejectUnsupportedResponsesInputTokenFields(raw)
		var aerr *AdapterError
		if !errors.As(err, &aerr) || aerr.Status != 400 || aerr.Context != "polyphemus" {
			t.Fatalf("input_tokens accepted %s: %v", body, err)
		}
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal([]byte(`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{}}`), &raw)
	if err := validateResponsesFields(raw, supportedResponsesCreateFields); err != nil {
		t.Fatalf("an empty options object on /v1/responses means defaults: %v", err)
	}
}

func TestPolyphemusKeyCaseVariantsAreRejectedEverywhere(t *testing.T) {
	for _, body := range []string{
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","Polyphemus":{}}`,
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","Polyphemus":null}`,
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":0.5},"POLYPHEMUS":null}`,
	} {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &raw); err != nil {
			t.Fatal(err)
		}
		for name, check := range map[string]func(map[string]json.RawMessage) error{
			"responses": RejectUnsupportedResponsesFields, "input_tokens": RejectUnsupportedResponsesInputTokenFields,
		} {
			var aerr *AdapterError
			if err := check(raw); !errors.As(err, &aerr) || aerr.Status != 400 {
				t.Fatalf("%s accepted %s: %v", name, body, err)
			}
		}
	}
}

func TestPolyphemusDuplicatesAreReadTheWayTheyWereValidated(t *testing.T) {
	// The raw map keeps the LAST duplicate; validation and the options both read it,
	// so an earlier invalid or unvalidated copy can neither error opaquely nor apply.
	for body, want := range map[string]any{
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"model_zoo":{}},"polyphemus":{"x_perf":0.5}}`:  0.5,
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":null},"polyphemus":{"x_perf":"a/b"}}`: "a/b",
		`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"x_perf":null,"x_perf":0.25}}`:                 0.25,
	} {
		req, err := decodeResponses([]byte(body))
		if err != nil || req.Polyphemus == nil || req.Polyphemus.XPerf != want {
			t.Fatalf("%s: %v %#v", body, err, req)
		}
	}
	req, err := decodeResponses([]byte(`{"model":"trustedrouter/polyphemus-1.0","input":"hi","polyphemus":{"modelZoo":"openai/*"},"polyphemus":{}}`))
	if err != nil || req.Polyphemus == nil || req.Polyphemus.ModelZoo != "" {
		t.Fatalf("an unvalidated earlier copy applied: %v %#v", err, req)
	}
}

func TestPolyphemusStructFieldIsNeverJSONDecoded(t *testing.T) {
	var req types.OpenAIResponsesRequest
	if err := json.Unmarshal([]byte(`{"model":"m","input":"hi","polyphemus":{"x_perf":0.5}}`), &req); err != nil || req.Polyphemus != nil {
		t.Fatalf("struct decoding populated options: %v %#v", err, req.Polyphemus)
	}
	var chat types.OpenAIChatRequest
	if err := json.Unmarshal([]byte(`{"model":"m","messages":[],"polyphemus":{"x_perf":0.5}}`), &chat); err != nil || chat.Polyphemus != nil {
		t.Fatalf("chat decoding populated options: %v %#v", err, chat.Polyphemus)
	}
}
