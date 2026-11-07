package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

func toolArgumentChunk(index int, id, name, arguments string) string {
	return fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":%d,\"id\":%q,\"function\":{\"name\":%q,\"arguments\":%q}}]}}]}\n\n", index, id, name, arguments)
}

func TestTranslateToolArgumentFragmentsPreserveEventsAndUsage(t *testing.T) {
	fragments := []struct {
		index int
		text  string
	}{
		{3, `{"text":"`},
		{1, `{"count":`},
		{3, strings.Repeat("x", 4096)},
		{1, "0}"},
		{3, `\"quoted\"\\line\n"}`},
	}
	var input strings.Builder
	input.WriteString(toolArgumentChunk(3, "call_first", "first", ""))
	input.WriteString(toolArgumentChunk(1, "call_second", "second", ""))
	for _, fragment := range fragments {
		input.WriteString(toolArgumentChunk(fragment.index, "", "", fragment.text))
	}
	input.WriteString("data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
	input.WriteString("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":5,\"prompt_tokens_details\":{\"cached_tokens\":900}}}\n\n")
	input.WriteString("data: [DONE]\n\n")

	var output bytes.Buffer
	if err := translateOpenAIStreamToAnthropic(strings.NewReader(input.String()), &output); err != nil {
		t.Fatal(err)
	}
	var starts, stops []int
	var gotFragments []struct {
		index int
		text  string
	}
	var usage map[string]int
	var reason string
	messageStops := 0
	for _, line := range strings.Split(output.String(), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var event struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
			Usage map[string]int `json:"usage"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			t.Fatal(err)
		}
		switch event.Type {
		case "content_block_start":
			starts = append(starts, event.Index)
			wantName := map[int]string{3: "first", 1: "second"}[event.Index]
			if event.ContentBlock.ID != "call_"+wantName || event.ContentBlock.Name != wantName {
				t.Fatal("tool identity changed")
			}
		case "content_block_delta":
			if event.Delta.Type != "input_json_delta" {
				t.Fatalf("unexpected delta type %q", event.Delta.Type)
			}
			gotFragments = append(gotFragments, struct {
				index int
				text  string
			}{event.Index, event.Delta.PartialJSON})
		case "content_block_stop":
			stops = append(stops, event.Index)
		case "message_delta":
			usage, reason = event.Usage, event.Delta.StopReason
		case "message_stop":
			messageStops++
		default:
			t.Fatalf("unexpected event %q", event.Type)
		}
	}
	if !reflect.DeepEqual(starts, []int{3, 1}) || !reflect.DeepEqual(stops, starts) || !reflect.DeepEqual(gotFragments, fragments) {
		t.Fatal("tool start/fragment/stop order or fragment bytes changed")
	}
	if usage["input_tokens"] != 1000 || usage["cache_read_input_tokens"] != 900 || reason != "tool_use" || messageStops != 1 {
		t.Fatalf("terminal usage/stop changed: %v, %q, %d", usage, reason, messageStops)
	}
	if outputTokens, reported := usage["output_tokens"]; !reported || outputTokens != 5 {
		t.Fatal("reported output usage lost")
	}
}

type toolFragmentReadFence struct {
	chunk string
	read  bool
}

func (r *toolFragmentReadFence) Read(p []byte) (int, error) {
	if r.read {
		return 0, errors.New("unexpected read after downstream failure")
	}
	r.read = true
	return copy(p, r.chunk), nil
}

type toolFragmentFailWriter struct {
	writes int
	err    error
}

func (w *toolFragmentFailWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 2 {
		return 0, w.err
	}
	return len(p), nil
}

func TestTranslateToolArgumentWriterFailureStopsReading(t *testing.T) {
	wantErr := errors.New("downstream closed")
	reader := &toolFragmentReadFence{chunk: toolArgumentChunk(0, "call_test", "test", `{"x":`)}
	writer := &toolFragmentFailWriter{err: wantErr}
	if err := translateOpenAIStreamToAnthropic(reader, writer); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want downstream failure", err)
	}
	if writer.writes != 2 {
		t.Fatalf("got %d writes, want immediate failure on argument delta", writer.writes)
	}
}

func BenchmarkTranslateToolArgumentFragments(b *testing.B) {
	for _, fragments := range []int{64, 256, 1024} {
		b.Run(fmt.Sprintf("fragments_%d", fragments), func(b *testing.B) {
			var input strings.Builder
			input.WriteString(toolArgumentChunk(0, "call_benchmark", "benchmark", `{"text":"`))
			chunk := toolArgumentChunk(0, "", "", strings.Repeat("x", 64))
			for range fragments {
				input.WriteString(chunk)
			}
			input.WriteString(toolArgumentChunk(0, "", "", `"}`))
			input.WriteString("data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n")
			stream := input.String()
			b.SetBytes(int64(len(stream)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := translateOpenAIStreamToAnthropic(strings.NewReader(stream), io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
