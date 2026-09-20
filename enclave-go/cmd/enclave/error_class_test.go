package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
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
		"ttfb_exceeded":      errors.New("llm/x: time-to-first-byte exceeded 8s"),
		"ctx_canceled":       errors.New("Post \"https://h\": context canceled"),
		"ctx_deadline":       errors.New("context deadline exceeded"),
		"upstream_5xx":       errors.New("llm/upstream: http 503: overloaded"),
		"rate_limited":       errors.New("llm/upstream: http 429: slow down"),
		"upstream_4xx":       errors.New("llm/upstream: http 404: no such model"),
		"unexpected_eof":     io.ErrUnexpectedEOF,
		"eof":                io.EOF,
		"conn_refused":       &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")},
		"conn_reset":         errors.New("read tcp 10.0.0.1:443: read: connection reset by peer"),
		"io_timeout":         errors.New("net/http: TLS handshake timeout: i/o timeout"),
		"dns_no_such_host":   errors.New("dial tcp: lookup api.example: no such host"),
		"http2_stream_error": errors.New("stream error: stream ID 3; INTERNAL_ERROR"),
		// The gateway's OWN conditions keep the values they were always logged
		// under: alerts match on them, and they were never anyone's content.
		"empty upstream response":       errEmptyUpstreamResponse,
		"user_model_first_byte_timeout": errUserModelFirstByteTimeout,
		"thinking_budget_exceeded":      errFusionOverthinkingBudget,
		"attestation_required":          errors.New("tinfoil: complete attestation verification required"),
	} {
		if got := errorClass(err); got != want {
			t.Errorf("errorClass(%v) = %q, want %q", err, got, want)
		}
	}
	if got := errorClass(nil); got != "" {
		t.Errorf("nil error: %q", got)
	}
	// An error nobody anticipated still says where it came from.
	if got := errorClass(fmt.Errorf("outer: %w", errors.New("inner"))); got != "other:*fmt.wrapError>*errors.errorString" {
		t.Errorf("type chain = %q", got)
	}
}
