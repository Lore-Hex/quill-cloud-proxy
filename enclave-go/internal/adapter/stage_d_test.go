package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

const stageDGoldenCreated = int64(1767225600)

func stageDGolden(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "stage_d", name))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func stageDDeterministicSSE(t *testing.T, wire []byte, created int64) []byte {
	t.Helper()
	if created <= 0 {
		t.Fatal("emitter did not report its created timestamp through the controlled sentinel")
	}
	return bytes.ReplaceAll(
		wire,
		[]byte(strconv.FormatInt(created, 10)),
		[]byte(strconv.FormatInt(stageDGoldenCreated, 10)),
	)
}

func stageDSuffixAt(t *testing.T, wire []byte, marker string) []byte {
	t.Helper()
	markerIndex := bytes.Index(wire, []byte(marker))
	if markerIndex < 0 {
		t.Fatalf("fixture start marker %q absent from SSE:\n%s", marker, wire)
	}
	if strings.HasPrefix(marker, "event: ") || strings.HasPrefix(marker, "data: ") {
		return wire[markerIndex:]
	}
	start := bytes.LastIndex(wire[:markerIndex], []byte("event: "))
	if start < 0 {
		start = bytes.LastIndex(wire[:markerIndex], []byte("data: "))
	}
	if start < 0 {
		t.Fatalf("SSE block start absent before marker %q", marker)
	}
	return wire[start:]
}

func assertStageDGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	want := stageDGolden(t, name)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from literal fixture\n--- got ---\n%s--- want ---\n%s", name, got, want)
	}
}

type terminalOrderWriter struct {
	settled *bool
	body    bytes.Buffer
}

func (w *terminalOrderWriter) Write(p []byte) (int, error) {
	if (bytes.Contains(p, []byte(`"finish_reason":"stop"`)) || bytes.Contains(p, []byte("event: response.completed"))) && !*w.settled {
		return 0, fmt.Errorf("terminal emitted before sentinel")
	}
	return w.body.Write(p)
}

func TestStageDChatSlicesBeforeEncodingAndSettlesBeforeTerminal(t *testing.T) {
	text := strings.Repeat("界", 220)
	provider := strings.NewReader(fmt.Sprintf("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":%q}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", text))
	settled := false
	writer := &terminalOrderWriter{settled: &settled}
	var slices []string
	result, err := TransformStreamCaptureControlled(provider, writer, "id", "model", false, nil, nil, &StreamControl{
		BeforeSlice: func(delta StreamDelta) error {
			slices = append(slices, delta.Text)
			return nil
		},
		BeforeTerminal: func(terminal StreamTerminal) error {
			if terminal.Result.Text != text {
				t.Fatalf("terminal text length=%d", len(terminal.Result.Text))
			}
			settled = true
			return terminal.Emit()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Text != text || len(slices) < 2 {
		t.Fatalf("result/slices = %d/%d", len(result.Text), len(slices))
	}
	for index, slice := range slices {
		if len([]byte(slice)) > MaxMeterChunkTokens*4 || !utf8.ValidString(slice) {
			t.Fatalf("slice %d invalid: %d", index, len([]byte(slice)))
		}
	}
}

func TestStageDHeartbeatLostUsesControlledChatTerminal(t *testing.T) {
	provider := strings.NewReader(stageDTextProvider())
	var output bytes.Buffer
	settled := false
	seen := 0
	var created int64
	_, err := TransformStreamCaptureControlled(provider, &output, "chatcmpl_stage_d", "fixture-model", false, nil, nil, &StreamControl{
		BeforeSlice: func(delta StreamDelta) error {
			if delta.Type == "text_delta" {
				seen++
			}
			if seen == 2 {
				return &ControlledTermination{FinishReason: "stop", TRFinishReason: "heartbeat_lost"}
			}
			return nil
		},
		BeforeTerminal: func(terminal StreamTerminal) error {
			created = terminal.Created
			settled = true
			return terminal.Emit()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !settled || !strings.Contains(output.String(), "first") || strings.Contains(output.String(), "second") || !strings.Contains(output.String(), `"tr_finish_reason":"heartbeat_lost"`) {
		t.Fatalf("settled=%t output=%s", settled, output.String())
	}
	deterministic := stageDDeterministicSSE(t, output.Bytes(), created)
	assertStageDGolden(t, "chat_heartbeat_lost.sse", stageDSuffixAt(t, deterministic, `"tr_finish_reason":"heartbeat_lost"`))
}

func TestStageDChatCapUsesControlledTerminalGolden(t *testing.T) {
	provider := strings.NewReader(stageDTextProvider())
	var output bytes.Buffer
	seen := 0
	settled := false
	var created int64
	_, err := TransformStreamCaptureControlled(provider, &output, "chatcmpl_stage_d", "fixture-model", false, nil, nil, &StreamControl{
		BeforeSlice: func(delta StreamDelta) error {
			if delta.Type == "text_delta" {
				seen++
			}
			if seen == 2 {
				return &ControlledTermination{FinishReason: "length", TRFinishReason: "cap_reached"}
			}
			return nil
		},
		BeforeTerminal: func(terminal StreamTerminal) error {
			created = terminal.Created
			settled = true
			return terminal.Emit()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wire := output.String()
	if !settled || strings.Contains(wire, "second") || !strings.Contains(wire, `"finish_reason":"length"`) || !strings.Contains(wire, `"tr_finish_reason":"cap_reached"`) {
		t.Fatalf("settled=%t wire=%s", settled, wire)
	}
	deterministic := stageDDeterministicSSE(t, output.Bytes(), created)
	assertStageDGolden(t, "chat_cap.sse", stageDSuffixAt(t, deterministic, `"tr_finish_reason":"cap_reached"`))
}

func TestStageDToolArgumentsAreSlicedBeforeEncoding(t *testing.T) {
	arguments := strings.Repeat("a", 600)
	provider := strings.NewReader(strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call_1","name":"lookup"}}`, "",
		`event: content_block_delta`,
		fmt.Sprintf(`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%q}}`, arguments), "",
		`event: content_block_stop`, `data: {"type":"content_block_stop","index":0}`, "",
		`event: message_stop`, `data: {"type":"message_stop"}`, "",
	}, "\n"))
	var output bytes.Buffer
	var slices []string
	_, err := TransformResponsesStreamControlled(provider, &output, "resp_test", "model", 1, nil, nil, nil, &StreamControl{
		BeforeSlice: func(delta StreamDelta) error { slices = append(slices, delta.Text); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(slices) != 3 || strings.Join(slices, "") != arguments {
		t.Fatalf("tool slices=%d", len(slices))
	}
	if strings.Count(output.String(), "event: response.function_call_arguments.delta") != 3 {
		t.Fatalf("output=%s", output.String())
	}
	if !strings.Contains(output.String(), `"name":"lookup"`) {
		t.Fatal("cohort arguments.done omitted function name")
	}
}

func TestStageDResponsesCapClosuresAreSchemaCompleteAndSequenced(t *testing.T) {
	tests := []struct {
		name, fixture, provider, marker string
		stop                            func(StreamDelta, int) bool
		want                            string
	}{
		{"text", "responses_cap_text.sse", stageDTextProvider(), "event: response.output_text.delta", func(delta StreamDelta, n int) bool { return delta.Type == "text_delta" && n == 2 }, `"type":"message"`},
		{"reasoning", "responses_cap_reasoning.sse", stageDReasoningProvider(), "event: response.reasoning_text.delta", func(delta StreamDelta, n int) bool { return delta.Type == "thinking_delta" && n == 2 }, `"type":"reasoning"`},
		{"function", "responses_cap_function_call.sse", stageDFunctionProvider(false), "event: response.function_call_arguments.delta", func(delta StreamDelta, n int) bool { return delta.Type == "input_json_delta" && n == 2 }, `"name":"lookup"`},
		{"mixed", "responses_cap_mixed.sse", stageDFunctionProvider(true), "event: response.output_text.delta", func(delta StreamDelta, n int) bool { return delta.Type == "text_delta" && n == 2 }, `"status":"completed"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			seen := map[string]int{}
			settled := false
			var created int64
			_, err := TransformResponsesStreamControlled(strings.NewReader(test.provider), &output, "resp_stage_d", "fixture-model", 1, nil, nil, nil, &StreamControl{
				BeforeSlice: func(delta StreamDelta) error {
					seen[delta.Type]++
					if test.stop(delta, seen[delta.Type]) {
						return &ControlledTermination{FinishReason: "length", TRFinishReason: "cap_reached"}
					}
					return nil
				},
				BeforeTerminal: func(terminal StreamTerminal) error {
					created = terminal.Created
					settled = true
					return terminal.Emit()
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			wire := output.String()
			for _, required := range []string{"event: response.incomplete", `"reason":"max_output_tokens"`, `"tr_finish_reason":"cap_reached"`, test.want, "data: [DONE]"} {
				if !strings.Contains(wire, required) {
					t.Fatalf("missing %s in %s", required, wire)
				}
			}
			if !settled || strings.Contains(wire, "event: response.completed") {
				t.Fatalf("settled=%t wire=%s", settled, wire)
			}
			assertStrictResponseSequences(t, wire)
			deterministic := stageDDeterministicSSE(t, output.Bytes(), created)
			assertStageDGolden(t, test.fixture, stageDSuffixAt(t, deterministic, test.marker))
		})
	}
}

func TestStageDResponsesHeartbeatLostUsesControlledTerminalGolden(t *testing.T) {
	var output bytes.Buffer
	settled := false
	seen := 0
	var created int64
	_, err := TransformResponsesStreamControlled(strings.NewReader(stageDTextProvider()), &output, "resp_stage_d", "fixture-model", 1, nil, nil, nil, &StreamControl{
		BeforeSlice: func(delta StreamDelta) error {
			if delta.Type == "text_delta" {
				seen++
			}
			if seen == 2 {
				return &ControlledTermination{FinishReason: "stop", TRFinishReason: "heartbeat_lost"}
			}
			return nil
		},
		BeforeTerminal: func(terminal StreamTerminal) error {
			created = terminal.Created
			settled = true
			return terminal.Emit()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wire := output.String()
	if !settled || !strings.Contains(wire, `"delta":"first"`) || strings.Contains(wire, `"delta":"second"`) || !strings.Contains(wire, `"tr_finish_reason":"heartbeat_lost"`) || strings.Contains(wire, "event: response.completed") {
		t.Fatalf("settled=%t wire=%s", settled, wire)
	}
	assertStrictResponseSequences(t, wire)
	deterministic := stageDDeterministicSSE(t, output.Bytes(), created)
	assertStageDGolden(t, "responses_heartbeat_lost.sse", stageDSuffixAt(t, deterministic, "event: response.output_text.delta"))
}

func stageDTextProvider() string {
	return "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"first\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"second\"}}\n\n"
}

func stageDReasoningProvider() string {
	return "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"first\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"second\"}}\n\n"
}

func stageDFunctionProvider(mixed bool) string {
	parts := []string{
		`event: content_block_start`, `data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call_1","name":"lookup"}}`, "",
		`event: content_block_delta`, `data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"first"}}`, "",
		`event: content_block_delta`, `data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"second"}}`, "",
	}
	if mixed {
		parts = append(parts,
			`event: content_block_stop`, `data: {"type":"content_block_stop","index":0}`, "",
			`event: content_block_delta`, `data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"first"}}`, "",
			`event: content_block_delta`, `data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"second"}}`, "",
		)
	}
	return strings.Join(parts, "\n")
}

func assertStrictResponseSequences(t *testing.T, wire string) {
	t.Helper()
	last := 0
	for _, block := range strings.Split(wire, "\n\n") {
		if block == "" || block == "data: [DONE]" {
			continue
		}
		var data string
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "data: ") {
				data = strings.TrimPrefix(line, "data: ")
			}
		}
		if data == "" {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			t.Fatal(err)
		}
		sequence, _ := payload["sequence_number"].(float64)
		if int(sequence) != last+1 {
			t.Fatalf("sequence=%v after %d in %s", sequence, last, block)
		}
		last = int(sequence)
	}
	if last == 0 {
		t.Fatal(io.EOF)
	}
}
