package upstreamerror

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type callerInputFailure struct{ err error }

func (e *callerInputFailure) Error() string              { return e.err.Error() }
func (e *callerInputFailure) Unwrap() error              { return e.err }
func (e *callerInputFailure) ClientInputMessage() string { return "invalid image input" }

// Redaction rebuilds a status-bearing error so no unsanitized body survives,
// but it must keep what the gateway knows about it: a caller-input failure
// (an image fetch whose control-plane call returned a 5xx) is not a provider
// failure, and neither is the gateway's own failure.
func TestCredentialRedactionPreservesClassificationMarkers(t *testing.T) {
	_, redact := WithCredentialRedaction(context.Background(), "secret-token")
	fetch := &callerInputFailure{err: errors.New("trustedrouter: /internal/gateway/fetch-image http 502: secret-token upstream body")}
	redacted := redact(fmt.Errorf("llm/provider: %w", fetch))
	var input interface{ ClientInputMessage() string }
	if !errors.As(redacted, &input) || input.ClientInputMessage() != "invalid image input" {
		t.Fatalf("caller-input marker dropped: %#v", redacted)
	}
	if strings.Contains(redacted.Error(), "secret-token") {
		t.Fatalf("credential survived redaction: %v", redacted)
	}
	if status, ok := Status(redacted); !ok || status != 502 {
		t.Fatalf("status = %d %t, want 502 kept", status, ok)
	}

	both := redact(&Local{Err: &callerInputFailure{err: errors.New("http 503: unavailable")}})
	if !IsLocal(both) || !errors.As(both, &input) {
		t.Fatalf("markers dropped: %#v", both)
	}
	plain := redact(errors.New("llm/provider: http 503: unavailable"))
	if IsLocal(plain) || errors.As(plain, &input) {
		t.Fatalf("an unmarked failure gained a marker: %#v", plain)
	}
}
