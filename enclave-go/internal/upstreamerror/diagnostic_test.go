package upstreamerror

import (
	"errors"
	"fmt"
	"testing"
)

func TestDiagnosticOnlyRetainsKnownMetadata(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"parameter", &Error{Status: 400, Body: `{"error":{"message":"PRIVATE prompt","code":"unsupported_parameter","param":"reasoning_effort"}}`}, "http=400;code=unsupported_parameter;param=reasoning_effort"},
		{"wrapped", fmt.Errorf("PRIVATE: %w", &Error{Status: 404, Body: `{"error":{"code":"model_not_found"}}`}), "http=404;code=model_not_found"},
		{"arbitrary metadata", &Error{Status: 400, Body: `{"error":{"message":"PRIVATE","type":"PRIVATE","code":"PRIVATE","param":"PRIVATE"}}`}, "http=400"},
		{"known field suffix", &Error{Status: 400, Body: `{"error":{"code":"model_not_found PRIVATE","param":"messages[0].PRIVATE"}}`}, "http=400"},
		{"html", &Error{Status: 503, Body: `<html>PRIVATE</html>`}, "http=503"},
		{"legacy", errors.New("llm/upstream: http 429: PRIVATE"), "http=429"},
		{"untyped", errors.New("PRIVATE"), ""},
		{"nil", nil, ""},
		{"invalid status", &Error{Status: 12345, Body: "PRIVATE"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Diagnostic(tt.err); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
