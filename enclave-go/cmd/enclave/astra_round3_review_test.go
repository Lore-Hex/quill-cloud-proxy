package main

import (
	"fmt"
	"strings"
	"testing"
)

// A logical retry storm keeps credential, route, body and billing inputs fixed.
// Attempt telemetry must not force a new authorization for every denied retry.
func TestAstraR3RetryTelemetryStorm(t *testing.T) {
	for route, body := range map[string]string{
		"/v1/chat/completions": astraChat,
		"/v1/responses":        `{"model":"test-model","input":"hi"}`,
		"/v1/messages":         `{"model":"test-model","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`,
		"/v1/embeddings":       `{"model":"test-model","input":"hi"}`,
		"/v1/images":           `{"model":"google/gemini-3.1-flash-image","prompt":"cat"}`,
		"/api/alpha/decide":    decideBody,
	} {
		for name, header := range map[string]func(int) string{
			"retry_count":  func(i int) string { return fmt.Sprintf("X-Stainless-Retry-Count: %d\r\n", i) },
			"timeout":      func(i int) string { return fmt.Sprintf("X-Stainless-Timeout: %d\r\n", 60-i) },
			"read_timeout": func(i int) string { return fmt.Sprintf("X-Stainless-Read-Timeout: 59.%03d\r\n", 999-i) },
			"tr_timing": func(i int) string {
				return fmt.Sprintf("X-TR-Client: v=1;a=1;po=http_error;pc=none;ph=apex;pm=%d;sm=%d;s=0;fo=0\r\n", 10+i, 20+i)
			},
		} {
			t.Run(route+"/"+name, func(t *testing.T) {
				gateway, calls := billingHeaderGateway(t)
				var logs string
				for i := 0; i < 5; i++ {
					response, requestLogs := astraRequest(t, gateway, route, body, header(i))
					if parseHTTPStatus(response) != 402 {
						t.Fatalf("attempt %d: %s", i, response)
					}
					logs += requestLogs
				}
				if *calls != 1 {
					t.Fatalf("5 billing-equivalent attempts caused %d authorize calls and %d request_end lines; want 1 authorize call", *calls, strings.Count(logs, "enclave.request_end"))
				}
			})
		}
	}
}
