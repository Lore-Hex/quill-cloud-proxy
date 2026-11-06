package adapter

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestZeroOutputUsageAcrossResponseAdapters(t *testing.T) {
	model := "deepseek/deepseek-v4.1-flash-1017"
	readers := map[string]func(io.Reader) (StreamResult, error){
		"buffered": CollectAnthropicText,
		"chat": func(r io.Reader) (StreamResult, error) {
			return TransformStreamCapture(r, io.Discard, "request", model)
		},
		"responses": func(r io.Reader) (StreamResult, error) {
			return TransformResponsesStream(r, io.Discard, "response", model, 2000, nil, nil)
		},
		"messages": func(r io.Reader) (StreamResult, error) {
			return RelayAnthropicStream(r, io.Discard, "message", model)
		},
	}
	for _, tc := range []struct {
		name, output string
		start, stop  bool
		want         bool
	}{
		{"explicit_zero", `,"output_tokens":0`, false, true, true},
		{"missing_output", "", false, true, false},
		{"null_output", `,"output_tokens":null`, false, true, false},
		{"negative_output", `,"output_tokens":-1`, false, true, false},
		{"string_output", `,"output_tokens":"0"`, false, true, false},
		{"start_placeholder", "", true, true, false},
		{"intermediate_zero", "", false, true, false},
		{"native_final_zero", `,"output_tokens":0`, true, true, true},
		{"truncated", `,"output_tokens":0`, false, false, false},
	} {
		for name, read := range readers {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				var stream strings.Builder
				if tc.name == "intermediate_zero" {
					stream.WriteString("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"output_tokens\":0}}\n\n")
				}
				if tc.start {
					stream.WriteString("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1000,\"output_tokens\":0}}}\n\n")
				}
				stream.WriteString(`event: message_delta` + "\ndata: " + `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":1000,"cache_read_input_tokens":900` + tc.output + "}}\n\n")
				if tc.stop {
					stream.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
				}
				result, err := read(strings.NewReader(stream.String()))
				if err != nil || result.Usage == nil {
					t.Fatalf("capture: usage=%#v err=%v", result.Usage, err)
				}
				if result.Usage.ZeroOutputReported != tc.want || result.Usage.InputTokens != 1000 || result.Usage.CacheReadInputTokens != 900 {
					t.Fatalf("usage=%#v, want confirmedZero=%v", result.Usage, tc.want)
				}
			})
		}
	}
}

func TestConfirmedZeroResponsesPublicUsageMatchesTerminalHook(t *testing.T) {
	stream := "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":1000,\"cache_read_input_tokens\":900,\"output_tokens\":0}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	var output bytes.Buffer
	hookCalled := false
	assertFields := func(fields map[string]any) {
		t.Helper()
		if getInt(fields, "input_tokens") != 1000 || getInt(fields, "output_tokens") != 0 || getInt(fields, "total_tokens") != 1000 || getInt(getMap(fields, "input_tokens_details"), "cached_tokens") != 900 {
			t.Fatalf("usage fields=%#v", fields)
		}
	}
	_, err := TransformResponsesStreamControlled(strings.NewReader(stream), &output, "response", "deepseek/deepseek-v4.1-flash-1017", 2000, nil, nil, nil, &StreamControl{
		ExposeResponsesUsage: true,
		BeforeTerminal: func(terminal StreamTerminal) error {
			hookCalled = true
			if terminal.Result.Usage == nil || !terminal.Result.Usage.ZeroOutputReported || terminal.Result.Usage.OutputTokens != 0 {
				t.Fatalf("terminal usage=%#v", terminal.Result.Usage)
			}
			assertFields(terminal.UsageFields)
			return terminal.Emit()
		},
	})
	if err != nil || !hookCalled {
		t.Fatalf("hook=%v err=%v", hookCalled, err)
	}
	completed := false
	for _, block := range strings.Split(output.String(), "\n\n") {
		name, event := parseSSEBlock([]byte(block))
		if name == "response.completed" {
			completed = true
			assertFields(getMap(getMap(event, "response"), "usage"))
		}
	}
	if !completed {
		t.Fatal("response.completed missing")
	}
}

func TestZeroOutputNotConfirmedOnErrorOrControlledTermination(t *testing.T) {
	stream := "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":1000,\"cache_read_input_tokens\":900,\"output_tokens\":0}}\n\n"
	failure := errors.New("injected stream failure")
	result, err := CollectAnthropicTextRetainingUsage(io.MultiReader(strings.NewReader(stream), iotest.ErrReader(failure)), nil)
	if !errors.Is(err, failure) || result.Usage == nil || result.Usage.ZeroOutputReported {
		t.Fatalf("retained usage=%#v err=%v", result.Usage, err)
	}
	for _, responses := range []bool{false, true} {
		observed := false
		control := &StreamControl{
			ObserveUsage: func(*StreamUsage) { observed = true },
			Termination: func() *ControlledTermination {
				if !observed {
					return nil
				}
				return &ControlledTermination{FinishReason: "length", TRFinishReason: "cap_exhausted"}
			},
		}
		if responses {
			result, err = TransformResponsesStreamControlled(strings.NewReader(stream), io.Discard, "response", "model", 2000, nil, nil, nil, control)
		} else {
			result, err = TransformStreamCaptureControlled(strings.NewReader(stream), io.Discard, "request", "model", false, nil, nil, control)
		}
		if err != nil || result.Usage == nil || result.Usage.ZeroOutputReported || result.FinishReason != "length" {
			t.Fatalf("controlled responses=%v usage=%#v finish=%q err=%v", responses, result.Usage, result.FinishReason, err)
		}
	}
}

func TestConfirmedZeroResponsesFoldsNativeFullyCachedInput(t *testing.T) {
	stream := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"cache_read_input_tokens\":900}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	var output bytes.Buffer
	hookCalled := false
	assertFields := func(fields map[string]any) {
		t.Helper()
		if getInt(fields, "input_tokens") != 900 || getInt(fields, "output_tokens") != 0 || getInt(fields, "total_tokens") != 900 || getInt(getMap(fields, "input_tokens_details"), "cached_tokens") != 900 {
			t.Fatalf("native cached usage=%#v", fields)
		}
	}
	_, err := TransformResponsesStreamControlled(strings.NewReader(stream), &output, "response", "native-model", 2000, nil, nil, nil, &StreamControl{
		ExposeResponsesUsage: true,
		BeforeTerminal: func(terminal StreamTerminal) error {
			hookCalled = true
			if terminal.Result.Usage == nil || terminal.Result.Usage.InputTokens != 0 || !terminal.Result.Usage.ZeroOutputReported || !terminal.Result.Usage.InputExcludesCache {
				t.Fatalf("native terminal usage=%#v", terminal.Result.Usage)
			}
			assertFields(terminal.UsageFields)
			return terminal.Emit()
		},
	})
	if err != nil || !hookCalled {
		t.Fatalf("hook=%v err=%v", hookCalled, err)
	}
	completed := false
	for _, block := range strings.Split(output.String(), "\n\n") {
		name, event := parseSSEBlock([]byte(block))
		if name == "response.completed" {
			completed = true
			assertFields(getMap(getMap(event, "response"), "usage"))
		}
	}
	if !completed {
		t.Fatal("response.completed missing")
	}
}
