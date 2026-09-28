package adapter

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func decodeResponses(body []byte) (*types.OpenAIResponsesRequest, error) {
	var req types.OpenAIResponsesRequest
	return &req, json.Unmarshal(body, &req)
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
