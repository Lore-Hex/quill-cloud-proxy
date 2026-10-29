//go:build llm_multi

package llm

import (
	"strings"
	"testing"
)

const runtimeStart = `{"type":"message_start","message":{"role":"assistant","usage":{"input_tokens":4,"output_tokens":0,"cache_read_input_tokens":8,"cache_creation_input_tokens":2}}}`
const runtimeFinal = `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`
const runtimeStop = `{"type":"message_stop"}`

func TestBedrockRuntimeStreamValidatesUsageAndOrder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events []string
	}{
		{"missing-start", []string{runtimeFinal}},
		{"duplicate-start", []string{runtimeStart, runtimeStart}},
		{"missing-final-usage", []string{runtimeStart, runtimeStop}},
		{"missing-stop-reason", []string{runtimeStart, `{"type":"message_delta","usage":{"output_tokens":2}}`, runtimeStop}},
		{"missing-output", []string{runtimeStart, `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{}}`}},
		{"fractional-output", []string{runtimeStart, strings.Replace(runtimeFinal, `:2`, `:2.5`, 1)}},
		{"null-output", []string{runtimeStart, strings.Replace(runtimeFinal, `:2`, `:null`, 1)}},
		{"negative-output", []string{runtimeStart, strings.Replace(runtimeFinal, `:2`, `:-1`, 1)}},
		{"overflow-output", []string{runtimeStart, strings.Replace(runtimeFinal, `:2`, `:9223372036854775808`, 1)}},
		{"missing-input", []string{strings.Replace(runtimeStart, `"input_tokens":4,`, "", 1)}},
		{"negative-cache", []string{strings.Replace(runtimeStart, `:8`, `:-1`, 1)}},
		{"regressed-usage", []string{runtimeStart, `{"type":"message_delta","usage":{"output_tokens":3}}`, runtimeFinal}},
		{"after-stop", []string{runtimeStart, runtimeFinal, runtimeStop, `{"type":"ping"}`}},
		{"content-after-final", []string{runtimeStart, runtimeFinal, `{"type":"content_block_delta"}`}},
		{"upstream-error", []string{runtimeStart, `{"type":"error","error":{"message":"private detail"}}`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var state bedrockRuntimeStream
			var err error
			for _, event := range tc.events {
				if _, err = state.accept([]byte(event)); err != nil {
					break
				}
			}
			if err == nil || strings.Contains(err.Error(), "private detail") {
				t.Fatalf("expected redacted failure, got %v", err)
			}
		})
	}
}

func TestBedrockRuntimeStreamCountsAreSnapshots(t *testing.T) {
	var state bedrockRuntimeStream
	for _, event := range []string{runtimeStart, `{"type":"message_delta","usage":{"output_tokens":1}}`, runtimeFinal, runtimeStop} {
		if _, err := state.accept([]byte(event)); err != nil {
			t.Fatal(err)
		}
	}
	if !state.stopped || state.usage["output_tokens"] != 2 || state.usage["input_tokens"] != 4 || state.usage["cache_read_input_tokens"] != 8 || state.usage["cache_creation_input_tokens"] != 2 {
		t.Fatalf("lost usage convention: %#v", state)
	}
}
