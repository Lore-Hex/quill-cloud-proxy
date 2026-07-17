package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

func TestUpstreamErrorResponseScrubsAndTruncatesUpstreamBody(t *testing.T) {
	prefix := "upstream http 404: "
	body := `{"error":"Bearer SECRET_TOKEN sk-AbCd_1234 ` + strings.Repeat("x", 1300) + `"}`
	code, message := upstreamErrorResponse(fmt.Errorf("llm/upstream: http 404: %s", body))

	if code != 404 {
		t.Fatalf("code = %d, want 404", code)
	}
	if !strings.HasPrefix(message, prefix) {
		t.Fatalf("message = %q, want prefix %q", message, prefix)
	}
	if len(message) != len(prefix)+1200 {
		t.Fatalf("message length = %d, want %d", len(message), len(prefix)+1200)
	}
	if strings.Contains(message, "SECRET_TOKEN") || strings.Contains(message, "sk-AbCd_1234") {
		t.Fatalf("message leaked secret: %q", message)
	}
	if !strings.Contains(message, "Bearer ***") || !strings.Contains(message, "sk-***") {
		t.Fatalf("message missing scrub markers: %q", message)
	}
}

func TestWriteStreamingProviderErrorEnrichesChatCompletionsFrame(t *testing.T) {
	var buf bytes.Buffer
	err := fmt.Errorf(`llm/upstream: http 404: {"error":"model not found"}`)
	if writeErr := writeStreamingProviderError(&buf, "chat.completions", "chatcmpl-test", "missing-model", err); writeErr != nil {
		t.Fatalf("write error: %v", writeErr)
	}

	frame := strings.SplitN(buf.String(), "\n\n", 2)[0]
	data := strings.TrimPrefix(frame, "data: ")
	var payload struct {
		Error struct {
			Message        string `json:"message"`
			Type           string `json:"type"`
			Source         string `json:"source"`
			UpstreamStatus int    `json:"status"`
		} `json:"error"`
	}
	if unmarshalErr := json.Unmarshal([]byte(data), &payload); unmarshalErr != nil {
		t.Fatalf("decode frame: %v; frame=%q", unmarshalErr, frame)
	}
	if payload.Error.Message != `upstream http 404: {"error":"model not found"}` {
		t.Fatalf("message = %q", payload.Error.Message)
	}
	if payload.Error.UpstreamStatus != 404 {
		t.Fatalf("upstream_status = %d, want 404", payload.Error.UpstreamStatus)
	}
	if payload.Error.Type != "provider_error" || payload.Error.Source != "provider" {
		t.Fatalf("error envelope changed: %#v", payload.Error)
	}
}

func TestWriteStreamingProviderErrorNilMatchesLegacyGenericFrame(t *testing.T) {
	var buf bytes.Buffer
	if err := writeStreamingProviderError(&buf, "chat.completions", "chatcmpl-test", "model", nil); err != nil {
		t.Fatalf("write error: %v", err)
	}
	const legacy = "data: {\"error\":{\"message\":\"provider error\",\"source\":\"provider\",\"type\":\"provider_error\"}}\n\ndata: [DONE]\n\n"
	if got := buf.String(); got != legacy {
		t.Fatalf("generic frame changed:\n got: %q\nwant: %q", got, legacy)
	}
}

func TestWriteAnthropicStreamErrorUsesEnrichedUpstreamMessage(t *testing.T) {
	_, message := upstreamErrorResponse(errors.New("llm/upstream: http 403: account disabled"))
	var buf bytes.Buffer
	if err := writeAnthropicStreamError(&buf, message); err != nil {
		t.Fatalf("write error: %v", err)
	}

	frame := strings.SplitN(buf.String(), "\n\n", 2)[0]
	data := strings.TrimPrefix(strings.TrimPrefix(frame, "event: error\n"), "data: ")
	var payload struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		t.Fatalf("decode frame: %v; frame=%q", err, frame)
	}
	if payload.Error.Message != "upstream http 403: account disabled" {
		t.Fatalf("message = %q", payload.Error.Message)
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

func TestWriteErrorWithSourceHeadersEmitsRetryAfter(t *testing.T) {
	var buf bytes.Buffer
	writeErrorWithSourceHeaders(&buf, 429, "API key daily spend limit exceeded", "router",
		map[string]string{"Retry-After": "1800"})
	out := buf.String()
	if !strings.Contains(out, "HTTP/1.1 429") {
		t.Fatalf("missing status line: %s", out)
	}
	if !strings.Contains(out, "Retry-After: 1800\r\n") {
		t.Fatalf("missing Retry-After header: %s", out)
	}
	if !strings.Contains(out, `"message":"API key daily spend limit exceeded"`) {
		t.Fatalf("missing body: %s", out)
	}
	// Header block must terminate before the body.
	if !strings.Contains(out, "\r\n\r\n{") {
		t.Fatalf("malformed header/body separation: %s", out)
	}
}

func TestAllowlistKeyInfoStatus(t *testing.T) {
	for _, s := range []int{200, 400, 401, 403, 404, 429, 503} {
		if got, relay := allowlistKeyInfoStatus(s); got != s || !relay {
			t.Fatalf("allowlistKeyInfoStatus(%d) = (%d,%v), want (%d,true)", s, got, relay, s)
		}
	}
	// Unexpected statuses collapse to 502 with relay=false so the body is
	// dropped — INCLUDING a raw 502, which must not be mistaken for expected.
	for _, s := range []int{100, 301, 302, 418, 500, 502, 504} {
		if got, relay := allowlistKeyInfoStatus(s); got != 502 || relay {
			t.Fatalf("allowlistKeyInfoStatus(%d) = (%d,%v), want (502,false)", s, got, relay)
		}
	}
}
