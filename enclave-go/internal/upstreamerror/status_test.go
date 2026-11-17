package upstreamerror

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestStatusDistinguishesStatuslessFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		ok     bool
	}{
		{"nil", nil, 0, false},
		{"typed", &Error{Status: 503, Body: `{"error":"unavailable"}`}, 503, true},
		{"wrapped typed", fmt.Errorf("invoke: %w", &Error{Status: 502, Body: "bad gateway"}), 502, true},
		{"message", errors.New("llm/fortanix: http 504: gateway timeout"), 504, true},
		{"client error", &Error{Status: 400, Body: "bad request"}, 400, true},
		{"refused connection", errors.New("llm/fortanix: invoke: dial tcp: connection refused"), 0, false},
		{"eof", fmt.Errorf("llm/fortanix: invoke: %w", io.EOF), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, ok := Status(tc.err)
			if status != tc.status || ok != tc.ok {
				t.Fatalf("Status() = %d, %t; want %d, %t", status, ok, tc.status, tc.ok)
			}
		})
	}
	// Parse keeps its 502 fallback for the same statusless failure.
	if got := Parse(errors.New("connection refused")); got.Status != 502 {
		t.Fatalf("Parse fallback status = %d, want 502", got.Status)
	}
}
