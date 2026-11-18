package upstreamerror

import (
	"errors"
	"testing"
)

const veniceOutOfFunds = `{"error":{"message":"Insufficient USD or Diem balance to complete request. Visit https://venice.ai/settings/api to add credits."}}`

func TestFundingExhaustedRecognizesProviderOutOfFundsReplies(t *testing.T) {
	for name, err := range map[string]error{
		// Incident 2026-11-18: Venice's own 402.
		"venice 402": &Error{Status: 402, Body: veniceOutOfFunds},
		// Any 402, whatever its body says.
		"bare 402": &Error{Status: 402, Body: "Payment Required"},
		// The same words under another 4xx.
		"venice words on 400": &Error{Status: 400, Body: veniceOutOfFunds},
		"anthropic 400":       &Error{Status: 400, Body: `{"type":"error","error":{"type":"invalid_request_error","message":"Your credit balance is too low to access the Anthropic API."}}`},
		"openai 429 code":     &Error{Status: 429, Body: `{"error":{"message":"You exceeded your current quota.","type":"insufficient_quota","code":"insufficient_quota"}}`},
		"wrapped text form":   errors.New("llm/venice: http 402: " + veniceOutOfFunds),
	} {
		if !FundingExhausted(err) {
			t.Errorf("%s: FundingExhausted = false, want true", name)
		}
	}
}

func TestFundingExhaustedIgnoresOtherFailures(t *testing.T) {
	for name, err := range map[string]error{
		"nil":           nil,
		"rate limit":    &Error{Status: 429, Body: `{"error":{"message":"Too many requests","type":"rate_limit_error"}}`},
		"bad request":   &Error{Status: 400, Body: `{"error":{"message":"max_tokens is too large"}}`},
		"overloaded":    &Error{Status: 503, Body: `{"error":{"message":"insufficient balance of GPUs"}}`},
		"transport":     errors.New("dial tcp: connection refused"),
		"local 402":     &Local{Err: &Error{Status: 402, Body: veniceOutOfFunds}},
		"model missing": &Error{Status: 404, Body: `{"error":{"message":"model not found"}}`},
	} {
		if FundingExhausted(err) {
			t.Errorf("%s: FundingExhausted = true, want false", name)
		}
	}
}

func TestDiagnosticMarksFundingWithoutProviderText(t *testing.T) {
	got := Diagnostic(&Error{Status: 400, Body: veniceOutOfFunds})
	if got != "http=400;funding" {
		t.Fatalf("Diagnostic = %q, want http=400;funding", got)
	}
	if got := Diagnostic(&Error{Status: 400, Body: `{"error":{"message":"max_tokens is too large"}}`}); got != "http=400" {
		t.Fatalf("Diagnostic = %q, want http=400", got)
	}
}
