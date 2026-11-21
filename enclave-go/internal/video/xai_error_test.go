package video

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// secretMarker stands in for anything the caller or xAI may put in an error:
// prompt text, an image data URL, an account detail. It must never survive.
// (Upper case so it names no request field; see field_mention_is_incidental.)
const secretMarker = "SECRET-PROMPT-ZZ9 DATA:IMAGE/PNG;BASE64,IVBORW0KGGO"

func queueXAIError(t *testing.T, status int, body string) *HTTPError {
	t.Helper()
	request := resolvedVideoRequest(t, CreateRequest{
		Model: "x-ai/grok-imagine-video", Prompt: secretMarker, Duration: 5,
		Resolution: "720p", AspectRatio: "16:9",
	})
	client := NewXAIClient("xai-secret", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(status, "application/json", body), nil
	})})
	_, err := client.QueueResolved(context.Background(), request)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("err = %v, want *HTTPError", err)
	}
	return httpErr
}

func TestXAIQueueErrorKeepsOnlyAllowlistedSymbols(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		// xAI's observed HTTP error shape: gRPC status description + message.
		{"known_code_and_field", `{"code":"Client specified an invalid argument","error":"Invalid request content: duration must be at most 10 for ` + secretMarker + `"}`, "http=400;code=invalid_argument;field=duration"},
		{"known_code_no_field", `{"code":"The caller does not have permission to execute the specified operation","error":"Team ` + secretMarker + ` is blocked"}`, "http=400;code=permission_denied"},
		// The documented job-error shape nests {code, message} under "error".
		{"nested_documented_code", `{"error":{"code":"invalid_argument","message":"resolution and aspect_ratio combination unsupported"}}`, "http=400;code=invalid_argument;field=aspect_ratio+resolution"},
		{"structured_param", `{"error":{"code":"invalid_argument","param":"image","message":"` + secretMarker + `"}}`, "http=400;code=invalid_argument;field=image"},
		// A message that merely echoes a field name (here inside a data URL)
		// still yields only that allowlisted name, never the surrounding text.
		{"field_mention_is_incidental", `{"code":"Client specified an invalid argument","error":"bad data:image/png;base64,AAAA"}`, "http=400;code=invalid_argument;field=image"},
		{"unknown_code_dropped", `{"code":"` + secretMarker + `","error":"nothing we know"}`, "http=400"},
		{"numeric_code_dropped", `{"code":"400","error":"Argument not supported: stream_options"}`, "http=400"},
		{"unknown_param_dropped", `{"error":{"param":"` + secretMarker + `","message":"x"}}`, "http=400"},
		{"non_json_body", secretMarker, "http=400"},
		{"empty_body", ``, "http=400"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			httpErr := queueXAIError(t, 400, tc.body)
			if got := httpErr.Diagnostic(); got != tc.want {
				t.Fatalf("Diagnostic() = %q, want %q", got, tc.want)
			}
			for _, rendered := range []string{httpErr.Diagnostic(), httpErr.Error()} {
				if strings.Contains(rendered, "SECRET") || strings.Contains(strings.ToLower(rendered), "base64") {
					t.Fatalf("provider text leaked: %q", rendered)
				}
			}
			assertAllowlisted(t, httpErr)
		})
	}
}

// Every symbol that can leave the classifier must be one of our own fixed
// labels or request field names, whatever the body says.
func assertAllowlisted(t *testing.T, httpErr *HTTPError) {
	t.Helper()
	if httpErr.Code != "" {
		known := false
		for _, label := range xaiErrorCodes {
			known = known || label == httpErr.Code
		}
		if !known {
			t.Fatalf("code %q is not an allowlisted label", httpErr.Code)
		}
	}
	for _, field := range httpErr.Fields {
		if !xaiVideoFields[field] {
			t.Fatalf("field %q is not an allowlisted request field", field)
		}
	}
}

func TestXAIQueueErrorReadsABoundedBody(t *testing.T) {
	// The code sits past the read limit, so it must not be seen at all.
	body := `{"error":"` + strings.Repeat("a", xaiErrorBodyLimit) + `","code":"Client specified an invalid argument"}`
	if got := queueXAIError(t, 422, body).Diagnostic(); got != "http=422" {
		t.Fatalf("Diagnostic() = %q, want http=422", got)
	}
}

func TestXAIQueueErrorKeepsStatusAndRetryability(t *testing.T) {
	httpErr := queueXAIError(t, 503, `{"code":"The service is currently unavailable","error":"busy"}`)
	if !httpErr.Retryable || httpErr.Diagnostic() != "http=503;code=unavailable" || httpErr.Error() != "grok http 503" {
		t.Fatalf("err = %#v diag=%q", httpErr, httpErr.Diagnostic())
	}
}

func TestHTTPErrorDiagnosticWithoutClassification(t *testing.T) {
	if got := (&HTTPError{Provider: "runway", Status: 400}).Diagnostic(); got != "http=400" {
		t.Fatalf("Diagnostic() = %q", got)
	}
	if got := (&HTTPError{Provider: "runway", Status: 200}).Diagnostic(); got != "" {
		t.Fatalf("Diagnostic() = %q for a non-error status", got)
	}
}
