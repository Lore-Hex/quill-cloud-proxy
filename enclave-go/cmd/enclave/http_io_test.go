package main

import (
	"bytes"
	"encoding/json"
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

func TestWriteErrorSources(t *testing.T) {
	cases := []struct {
		name   string
		write  func(*bytes.Buffer)
		source string
	}{
		{
			name: "router default",
			write: func(buf *bytes.Buffer) {
				writeError(buf, 400, "bad request")
			},
			source: "router",
		},
		{
			name: "provider explicit",
			write: func(buf *bytes.Buffer) {
				writeProviderError(buf, 502, "provider error")
			},
			source: "provider",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.write(&buf)
			body := httpBody(t, buf.String())
			var payload map[string]map[string]any
			if err := json.Unmarshal([]byte(body), &payload); err != nil {
				t.Fatalf("json: %v\nbody=%s", err, body)
			}
			if got := payload["error"]["source"]; got != tc.source {
				t.Fatalf("source = %v, want %q; body=%s", got, tc.source, body)
			}
		})
	}
}

func TestAnthropicProviderErrorSource(t *testing.T) {
	var buf bytes.Buffer
	writeAnthropicProviderError(&buf, 429, "rate limited")
	body := httpBody(t, buf.String())
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("json: %v\nbody=%s", err, body)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error payload: %#v", payload)
	}
	if got := errorPayload["source"]; got != "provider" {
		t.Fatalf("source = %v, want provider; body=%s", got, body)
	}
}

func httpBody(t *testing.T, raw string) string {
	t.Helper()
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("missing HTTP body separator: %q", raw)
	}
	return parts[1]
}
