package adapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestIncompleteResponsesPreserveConfirmedZeroCacheUsage(t *testing.T) {
	for _, tc := range []struct {
		name      string
		prefix    string
		usage     string
		wantInput int
	}{
		{"inclusive_input", "", `{"input_tokens":1000,"cache_read_input_tokens":900,"output_tokens":0}`, 1000},
		{"native_full_cache", "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"cache_read_input_tokens\":900}}}\n\n", `{"output_tokens":0}`, 900},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := tc.prefix + "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"},\"usage\":" + tc.usage + "}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
			assertUsage := func(fields map[string]any) {
				t.Helper()
				if getInt(fields, "input_tokens") != tc.wantInput || getInt(fields, "output_tokens") != 0 || getInt(fields, "total_tokens") != tc.wantInput || getInt(getMap(fields, "input_tokens_details"), "cached_tokens") != 900 {
					t.Fatalf("usage=%#v", fields)
				}
			}
			assertResponse := func(response map[string]any) {
				t.Helper()
				if response["status"] != "incomplete" || response["completed_at"] != nil || getMap(response, "incomplete_details")["reason"] != "max_output_tokens" {
					t.Fatalf("response=%#v", response)
				}
				assertUsage(getMap(response, "usage"))
			}
			var output bytes.Buffer
			hooks := 0
			result, err := TransformResponsesStreamControlled(strings.NewReader(stream), &output, "response", "model", 2000, nil, nil, nil, &StreamControl{
				ExposeResponsesUsage: true,
				BeforeTerminal: func(terminal StreamTerminal) error {
					hooks++
					if terminal.Result.FinishReason != "length" || terminal.Result.Usage == nil || !terminal.Result.Usage.ZeroOutputReported {
						t.Fatalf("terminal=%#v", terminal.Result)
					}
					assertUsage(terminal.UsageFields)
					return terminal.Emit()
				},
			})
			if err != nil || hooks != 1 || result.Usage == nil {
				t.Fatalf("hooks=%d usage=%#v err=%v", hooks, result.Usage, err)
			}
			terminals := 0
			for _, block := range strings.Split(output.String(), "\n\n") {
				name, event := parseSSEBlock([]byte(block))
				if name == "response.completed" {
					t.Fatal("length stop emitted response.completed")
				}
				if name == "response.incomplete" {
					terminals++
					assertResponse(getMap(event, "response"))
				}
			}
			if terminals != 1 {
				t.Fatalf("incomplete terminal count=%d, want 1", terminals)
			}
			var buffered bytes.Buffer
			if err := WriteResponsesResponse(&buffered, "response", "model", result.Text, result.ToolCalls, result.FinishReason, result.Usage.InputTokens, result.Usage.OutputTokens, result.Usage, 123, nil, nil); err != nil {
				t.Fatal(err)
			}
			var response map[string]any
			if err := json.Unmarshal(buffered.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			assertResponse(response)
		})
	}
}

func TestStampedResponsesPreserveConfirmedZeroCacheUsage(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, usage string
		rawInput, fullInput int
		excludesCache       bool
	}{
		{"inclusive_input", "", `{"input_tokens":1000,"cache_read_input_tokens":900,"output_tokens":0}`, 1000, 1000, false},
		{"native_full_cache", "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":0,\"cache_read_input_tokens\":900,\"output_tokens\":0}}}\n\n", `{"output_tokens":0}`, 0, 900, true},
	} {
		for _, ending := range []struct {
			name     string
			terminal bool
		}{{"confirmed", true}, {"missing_terminal", false}} {
			t.Run(tc.name+"/"+ending.name, func(t *testing.T) {
				stream := tc.prefix + strings.Join([]string{
					"event: content_block_start",
					`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"web_search"}}`,
					"", "event: content_block_delta",
					`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}`,
					"", "event: message_delta",
					`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":` + tc.usage + `}`,
					"", "",
				}, "\n")
				if ending.terminal {
					stream += "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
				}
				assertUsage := func(usage *StreamUsage) {
					t.Helper()
					if usage == nil || usage.InputTokens != tc.rawInput || usage.InputExcludesCache != tc.excludesCache || usage.CacheReadInputTokens != 900 || usage.OutputTokens != 0 || usage.ZeroOutputReported != ending.terminal {
						t.Fatalf("usage=%#v, confirmed=%v", usage, ending.terminal)
					}
				}
				assertFields := func(fields map[string]any) {
					t.Helper()
					output := getInt(fields, "output_tokens")
					if getInt(fields, "input_tokens") != tc.fullInput || getInt(fields, "total_tokens") != tc.fullInput+output || getInt(getMap(fields, "input_tokens_details"), "cached_tokens") != 900 {
						t.Fatalf("public usage=%#v", fields)
					}
					if (ending.terminal && output != 0) || (!ending.terminal && output <= 0) {
						t.Fatalf("output=%d, confirmed=%v", output, ending.terminal)
					}
				}
				assertResponse := func(response map[string]any) {
					t.Helper()
					assertFields(getMap(response, "usage"))
					items, ok := response["output"].([]any)
					if !ok || len(items) != 1 {
						t.Fatalf("output=%#v", response["output"])
					}
					item, ok := items[0].(map[string]any)
					if !ok || item["call_id"] != "pinned_toolu_01" || item["name"] != "web_search" || item["arguments"] != "{}" {
						t.Fatalf("function call=%#v", items[0])
					}
				}
				var output bytes.Buffer
				hooks, stamps := 0, 0
				result, err := TransformResponsesStreamControlled(strings.NewReader(stream), &output, "response", "model", 2000, nil, nil, nil, &StreamControl{
					ExposeResponsesUsage: true,
					ToolCallID: func(id string) string {
						stamps++
						return "pinned_" + id
					},
					BeforeTerminal: func(terminal StreamTerminal) error {
						hooks++
						assertUsage(terminal.Result.Usage)
						assertFields(terminal.UsageFields)
						return terminal.Emit()
					},
				})
				if err != nil || hooks != 1 || stamps != 1 {
					t.Fatalf("hooks=%d stamps=%d err=%v", hooks, stamps, err)
				}
				assertUsage(result.Usage)
				if len(result.ToolCalls) != 1 || result.ToolCalls[0].ID != "toolu_01" || result.ToolCalls[0].CallID != "pinned_toolu_01" {
					t.Fatalf("tool calls=%#v", result.ToolCalls)
				}
				terminals := 0
				for _, block := range strings.Split(output.String(), "\n\n") {
					name, event := parseSSEBlock([]byte(block))
					if name == "response.completed" {
						terminals++
						assertResponse(getMap(event, "response"))
					}
				}
				if terminals != 1 {
					t.Fatalf("terminal count=%d", terminals)
				}
				if ending.terminal {
					var buffered bytes.Buffer
					if err := WriteResponsesResponse(&buffered, "response", "model", result.Text, result.ToolCalls, result.FinishReason, result.Usage.InputTokens, 0, result.Usage, 123, nil, nil); err != nil {
						t.Fatal(err)
					}
					var response map[string]any
					if err := json.Unmarshal(buffered.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					assertResponse(response)
				}
			})
		}
	}
}

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
