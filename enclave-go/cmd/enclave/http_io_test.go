package main

import (
	"errors"
	"strings"
	"testing"
)

// upstreamErrorResponse must surface the real upstream status + message when the
// provider client wrapped an HTTP failure as "...http <status>: <body>", so a
// client sees e.g. a 400 "max_tokens too large" instead of an opaque 502. The
// non-streaming chat + responses paths rely on this (they used to hardcode 502).
func TestUpstreamErrorResponse(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantCode  int
		wantInMsg string
	}{
		{"nil", nil, 502, "provider error"},
		{
			"max_tokens 400 surfaced",
			errors.New(`openai_compatible: http 400: {"error":{"message":"max_tokens is too large: maximum is 16384"}}`),
			400, "max_tokens is too large",
		},
		{"upstream 500 surfaced", errors.New("provider: http 500: internal error"), 500, "internal error"},
		{"unclassifiable stays 502", errors.New("connection reset by peer"), 502, "provider error"},
		{"out-of-range code ignored", errors.New("weird http 999: nope"), 502, "provider error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, msg := upstreamErrorResponse(tc.err)
			if code != tc.wantCode {
				t.Fatalf("code = %d, want %d (msg=%q)", code, tc.wantCode, msg)
			}
			if !strings.Contains(msg, tc.wantInMsg) {
				t.Fatalf("msg = %q, want to contain %q", msg, tc.wantInMsg)
			}
		})
	}
}
