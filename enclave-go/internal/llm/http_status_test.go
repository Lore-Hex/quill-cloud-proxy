package llm

import (
	"errors"
	"fmt"
	"testing"
)

func TestHTTPStatusFromError(t *testing.T) {
	if s, ok := HTTPStatusFromError(&upstreamHTTPError{status: 502, body: "boom"}); !ok || s != 502 {
		t.Fatalf("direct: got (%d, %v), want (502, true)", s, ok)
	}
	// errors.As unwraps, so a wrapped upstream error still yields its status.
	if s, ok := HTTPStatusFromError(fmt.Errorf("attempt failed: %w", &upstreamHTTPError{status: 404})); !ok || s != 404 {
		t.Fatalf("wrapped: got (%d, %v), want (404, true)", s, ok)
	}
	if _, ok := HTTPStatusFromError(errors.New("dial tcp: connection refused")); ok {
		t.Fatal("transport error should not yield an HTTP status")
	}
	if _, ok := HTTPStatusFromError(nil); ok {
		t.Fatal("nil should not yield an HTTP status")
	}
}
