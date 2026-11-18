package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/maple"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamcert"
)

// errorClass feeds log lines on every route. It used to fall back to the first
// 80 characters of the error's text, which is whatever the error's author put
// there: a vendor quoting the prompt it rejected, a decoder quoting the literal
// it choked on.
func TestErrorClassNeverReturnsTheErrorsOwnText(t *testing.T) {
	const secret = "PRIVATE-STATE charged twice"
	for label, err := range map[string]error{
		"plain":          errors.New("vendor rejected state: " + secret),
		"wrapped":        fmt.Errorf("invoke: %w", errors.New("rejected: "+secret)),
		"decoder quote":  fmt.Errorf(`strconv.ParseFloat: parsing %q: value out of range`, secret),
		"beside a known": fmt.Errorf("unexpected EOF after %s", secret),
		"long":           errors.New(strings.Repeat("x", 200) + secret),
		"unknown phase":  &upstreamcert.SetupError{Phase: secret, Err: context.DeadlineExceeded},
	} {
		class := errorClass(err)
		if strings.Contains(class, "PRIVATE") || strings.Contains(class, "charged") || strings.Contains(class, "rejected") {
			t.Errorf("%s: class %q carries the error's text", label, class)
		}
		if class == "" {
			t.Errorf("%s: empty class", label)
		}
	}
}

func TestErrorClassKeepsWhatOperatorsReadItFor(t *testing.T) {
	for want, err := range map[string]error{
		"ttfb_exceeded":        errors.New("llm/x: time-to-first-byte exceeded 8s"),
		"ctx_canceled":         errors.New("Post \"https://h\": context canceled"),
		"ctx_deadline":         errors.New("context deadline exceeded"),
		"connect_dial_timeout": &upstreamcert.SetupError{Phase: "dial", Err: context.DeadlineExceeded},
		"connect_tls_timeout":  fmt.Errorf("provider: %w", &upstreamcert.SetupError{Phase: "tls", Err: context.DeadlineExceeded}),
		"upstream_5xx":         errors.New("llm/upstream: http 503: overloaded"),
		"rate_limited":         errors.New("llm/upstream: http 429: slow down"),
		"upstream_4xx":         errors.New("llm/upstream: http 404: no such model"),
		"unexpected_eof":       io.ErrUnexpectedEOF,
		"eof":                  io.EOF,
		"conn_refused":         &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")},
		"conn_reset":           errors.New("read tcp 10.0.0.1:443: read: connection reset by peer"),
		"io_timeout":           errors.New("net/http: TLS handshake timeout: i/o timeout"),
		"dns_no_such_host":     errors.New("dial tcp: lookup api.example: no such host"),
		"http2_stream_error":   errors.New("stream error: stream ID 3; INTERNAL_ERROR"),
		// The gateway's OWN conditions keep the values they were always logged
		// under: alerts match on them, and they were never anyone's content.
		"empty upstream response":       errEmptyUpstreamResponse,
		"user_model_first_byte_timeout": errors.New("user-model first-byte budget exceeded"),
		"thinking_budget_exceeded":      errFusionOverthinkingBudget,
		"attestation_required":          errors.New("tinfoil: complete attestation verification required"),
		"downstream_closed":             io.ErrClosedPipe,
	} {
		if got := errorClass(err); got != want {
			t.Errorf("errorClass(%v) = %q, want %q", err, got, want)
		}
	}
	if got := errorClass(nil); got != "" {
		t.Errorf("nil error: %q", got)
	}
	// The settlement marker says WHEN a failure happened, not where it came
	// from, so it is not part of the chain.
	if got := errorClass(&settlementAttemptedError{fmt.Errorf("outer: %w", errors.New("inner"))}); got != "other:*fmt.wrapError>*errors.errorString" {
		t.Errorf("type chain through the settlement marker = %q", got)
	}
	// An error nobody anticipated still says where it came from.
	if got := errorClass(fmt.Errorf("outer: %w", errors.New("inner"))); got != "other:*fmt.wrapError>*errors.errorString" {
		t.Errorf("type chain = %q", got)
	}
}

type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

// A stream that dies writing to the client must be attributed to the client,
// not logged as a provider failure.
func TestStreamStatsWriterRecordsFirstClientWriteError(t *testing.T) {
	timeout := &net.OpError{Op: "write", Net: "tcp", Err: errors.New("i/o timeout")}
	w := newStreamStatsWriter(failingWriter{err: timeout})
	if w.ClientWriteErr() != nil {
		t.Fatal("error before any write")
	}
	_, _ = w.Write([]byte("data: x\n\n"))
	_, _ = w.Write([]byte("data: y\n\n"))
	if got := w.ClientWriteErr(); got != timeout {
		t.Fatalf("ClientWriteErr = %v, want the first write error", got)
	}
	if got := errorClass(w.ClientWriteErr()); got != "io_timeout" {
		t.Fatalf("class = %q", got)
	}
	ok := newStreamStatsWriter(io.Discard)
	_, _ = ok.Write([]byte("data: z\n\n"))
	if ok.ClientWriteErr() != nil {
		t.Fatal("successful writes recorded an error")
	}
}

// 2026-11-16: a Maple front-enclave rotation logged only
// err="other:*errors.errorString" for two days. Each fixed Maple start failure
// now has its own label, recognised by value (llm/maple keeps the old text),
// and labelling changes no circuit decision: none was ever a provider-down
// failure.
func TestErrorClassNamesMapleStartFailures(t *testing.T) {
	for want, err := range map[string]error{
		"maple_attestation_rejected":      maple.ErrAttestationRejected,
		"maple_request_failed":            maple.ErrRequestFailed,
		"maple_response_start_timeout":    maple.ErrResponseStartTimeout,
		"maple_adapter_setup_failed":      maple.ErrAdapterSetupFailed,
		"maple_adapter_input_rejected":    maple.ErrAdapterInputRejected,
		"maple_capacity_exhausted":        maple.ErrCapacityExhausted,
		"maple_adapter_unavailable":       maple.ErrAdapterUnavailable,
		"maple_no_adapter_status":         maple.ErrInvalidAdapterStatus,
		"maple_upstream_error_unreadable": maple.ErrUpstreamErrorUnreadable,
		"maple_start_failed":              errors.New("llm/maple: encrypted request verification failed"),
		"maple_response_invalid":          errors.New("llm/maple: encrypted response incomplete or invalid"),
	} {
		candidates := []error{err}
		if maple.StartFailure(err) != nil {
			// A value label survives wrapping, whatever text surrounds it.
			candidates = append(candidates, fmt.Errorf("llm/maple: encrypted request verification failed: %w", err))
		}
		for _, candidate := range candidates {
			if got := errorClass(candidate); got != want {
				t.Errorf("errorClass(%v) = %q, want %q", candidate, got, want)
			}
			if providerDownFailure(candidate, false) || providerDownFailure(candidate, true) {
				t.Errorf("%v now counts as provider down", candidate)
			}
		}
	}
	// Text alone never earns a value label.
	if got := errorClass(errors.New("maple: front enclave attestation rejected")); got == "maple_attestation_rejected" {
		t.Errorf("a look-alike error got the attestation label")
	}
	// A Maple start the gateway's first-byte timer or a cancellation cut short
	// keeps that label (operators filter on ttfb_exceeded), as on main.
	for want, err := range map[string]error{
		"ttfb_exceeded": fmt.Errorf("llm/upstream: time-to-first-byte exceeded 20s: %w", maple.ErrInvalidAdapterStatus),
		"ctx_canceled":  fmt.Errorf("maple start: context canceled: %w", maple.ErrInvalidAdapterStatus),
	} {
		if got := errorClass(err); got != want {
			t.Errorf("errorClass(%v) = %q, want %q", err, got, want)
		}
	}
}
