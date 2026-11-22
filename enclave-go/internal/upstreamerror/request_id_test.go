package upstreamerror

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type requestIDError struct {
	status int
	id     string
}

func (e *requestIDError) Error() string                   { return "provider error" }
func (e *requestIDError) UpstreamResponse() (int, string) { return e.status, "" }

func (e *requestIDError) UpstreamRequestID() string { return e.id }

func TestRequestIDAdmitsOnlyBoundedPlainIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want string
	}{
		{"req_0123abcd", "req_0123abcd"},
		{"7f1c2b3a-9d8e-4f00-a1b2-c3d4e5f60718", "7f1c2b3a-9d8e-4f00-a1b2-c3d4e5f60718"},
		{"", ""},
		{"id with space", ""},
		{"id\r\nX-Injected: 1", ""},
		{`id"quote`, ""},
		{strings.Repeat("a", 97), ""},
		{"sk-" + "a1B2c3D4e5F6g7H8", ""},
	} {
		err := fmt.Errorf("llm/boundless: %w", &requestIDError{status: 400, id: tc.id})
		if got := RequestID(err); got != tc.want {
			t.Errorf("RequestID(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestRequestIDIsEmptyWithoutACarrier(t *testing.T) {
	if got := RequestID(&Error{Status: 400, Body: `{"error":{"message":"x"}}`}); got != "" {
		t.Fatalf("RequestID = %q, want empty", got)
	}
	if got := RequestID(errors.New("dial tcp: refused")); got != "" {
		t.Fatalf("RequestID = %q, want empty", got)
	}
	if got := RequestID(nil); got != "" {
		t.Fatalf("RequestID(nil) = %q, want empty", got)
	}
}
