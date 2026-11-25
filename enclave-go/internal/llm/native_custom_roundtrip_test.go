package llm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func customTestEvents(t *testing.T, parts []string) string {
	t.Helper()
	var s strings.Builder
	event := func(v map[string]any) {
		p, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&s, "data: %s\n\n", p)
	}
	item := map[string]any{"type": "custom_tool_call", "call_id": "call_xyz", "id": "ctc_123", "name": "patch", "input": ""}
	event(map[string]any{"type": "response.output_item.added", "output_index": 0, "item": item})
	for _, part := range parts {
		event(map[string]any{"type": "response.custom_tool_call_input.delta", "item_id": item["id"], "output_index": 0, "delta": part})
	}
	item["input"] = strings.Join(parts, "")
	event(map[string]any{"type": "response.custom_tool_call_input.done", "item_id": item["id"], "output_index": 0, "input": item["input"]})
	event(map[string]any{"type": "response.output_item.done", "output_index": 0, "item": item})
	fmt.Fprintf(&s, "data: %s\n\n", responsesTestTerminal)
	return s.String()
}

func TestNativeCustomToolRoundTrip(t *testing.T) {
	parts := []string{"@@ -1 +1 @@\n", "-old\n", "+new <&> \"quoted\"\n"}
	input := strings.Join(parts, "")
	grammar := map[string]any{"type": "grammar", "syntax": "regex", "definition": "(?s).+"}
	tool := map[string]any{"type": "custom", "name": "patch", "format": grammar}
	choice := map[string]any{"type": "custom", "name": "patch"}
	for _, model := range []string{"openai/gpt-5.5", "openai/gpt-6.2-astra"} {
		t.Run(model, func(t *testing.T) {
			req := &qtypes.OpenAIResponsesRequest{Model: model, Input: "neutral fixture", Tools: []any{tool}, ToolChoice: choice}
			var replay map[string]any
			for turn := 0; turn < 2; turn++ {
				if turn == 1 {
					req.Tools, req.ToolChoice = nil, nil
					req.Input = []any{replay, map[string]any{"type": "custom_tool_call_output", "call_id": replay["call_id"], "output": "accepted"}}
				}
				chat, err := adapter.ResponsesToChat(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := adapter.ToAnthropic(chat, model)
				if err != nil {
					t.Fatal(err)
				}
				requests := 0
				client := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					requests++
					var wire map[string]any
					if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
						t.Fatal(err)
					}
					if r.URL.Path != "/v1/responses" || wire["store"] != false {
						t.Fatal("wrong endpoint or retention")
					}
					response := "data: " + responsesTestTerminal + "\n\n"
					if turn == 0 {
						if !reflect.DeepEqual(wire["tools"], []any{tool}) || !reflect.DeepEqual(wire["tool_choice"], choice) {
							t.Fatal("native declaration or grammar changed")
						}
						response = customTestEvents(t, parts)
					} else {
						want := []any{map[string]any{"type": "custom_tool_call", "name": "patch", "call_id": "call_xyz", "input": input}, map[string]any{"type": "custom_tool_call_output", "call_id": "call_xyz", "output": "accepted"}}
						if !reflect.DeepEqual(wire["input"], want) {
							t.Fatalf("wrong continuation: %#v", wire["input"])
						}
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}, nil
				})}
				credits := &openAICompatibleClient{provider: "openai", baseURL: "https://example.invalid/v1", apiKey: "fixture", httpc: client}
				var internal bytes.Buffer
				if err := credits.InvokeStreaming(t.Context(), chat, body, &internal, InvokeOptions{Provider: "openai", UsageType: "Credits", UpstreamModel: strings.TrimPrefix(model, "openai/")}); err != nil {
					t.Fatal(err)
				}
				if requests != 1 {
					t.Fatalf("got %d upstream requests", requests)
				}
				if turn == 1 {
					continue
				}
				result, err := adapter.CollectAnthropicTextStrict(bytes.NewReader(internal.Bytes()))
				if err != nil || result.Usage == nil || len(result.ToolCalls) != 1 {
					t.Fatalf("missing call or usage: %v", err)
				}
				var out bytes.Buffer
				if err := adapter.WriteResponsesResponse(&out, "resp_1", model, "", result.ToolCalls, result.FinishReason, 100, 30, result.Usage, 1, nil, chat.Response); err != nil {
					t.Fatal(err)
				}
				var jsonResp struct{ Output []map[string]any }
				if err := json.Unmarshal(out.Bytes(), &jsonResp); err != nil {
					t.Fatal(err)
				}
				if len(jsonResp.Output) != 1 {
					t.Fatal("missing custom output")
				}
				replay = jsonResp.Output[0]
				if replay["type"] != "custom_tool_call" || replay["call_id"] != "call_xyz" || replay["input"] != input || replay["arguments"] != nil {
					t.Fatalf("bad custom item: %#v", replay)
				}
				out.Reset()
				if _, err := adapter.TransformResponsesStream(bytes.NewReader(internal.Bytes()), &out, "resp_1", model, 100, nil, chat.Response); err != nil {
					t.Fatal(err)
				}
				var deltas []string
				done, terminal := false, false
				for _, line := range strings.Split(out.String(), "\n") {
					if !strings.HasPrefix(line, "data: {") {
						continue
					}
					var e map[string]any
					if err := json.Unmarshal([]byte(line[6:]), &e); err != nil {
						t.Fatal(err)
					}
					switch e["type"] {
					case "response.custom_tool_call_input.delta":
						deltas = append(deltas, e["delta"].(string))
					case "response.custom_tool_call_input.done":
						done = e["input"] == input
					case "response.completed":
						terminal = true
					case "response.function_call_arguments.delta", "response.function_call_arguments.done":
						t.Fatal("custom tool converted to a function")
					}
				}
				if !reflect.DeepEqual(parts, deltas) || !done || !terminal {
					t.Fatal("lost custom stream framing or fragments")
				}
			}
		})
	}
}

func TestNativeCustomStreamRejectsMismatches(t *testing.T) {
	fixture := customTestEvents(t, []string{"example"})
	meta := &qtypes.NativeCustomTools{Definitions: map[string]map[string]any{"patch": {"type": "custom"}}}
	for _, s := range []string{
		strings.Replace(fixture, `"delta":"example"`, `"delta":"different"`, 1),
		strings.Replace(fixture, "response.custom_tool_call_input.delta", "response.function_call_arguments.delta", 1),
		strings.Replace(fixture, `"item_id":"ctc_123"`, `"item_id":"wrong"`, 1),
		strings.Replace(fixture, "response.custom_tool_call_input.done", "unknown", 1),
		strings.Replace(fixture, `"name":"patch"`, `"name":"other"`, 1),
		strings.Replace(fixture, "response.output_item.done", "unknown", 1),
	} {
		if err := translateNativeResponsesStream(strings.NewReader(s), io.Discard, meta); err == nil {
			t.Fatal("malformed custom call accepted")
		}
	}
}

func TestNativeCustomTruncatedCallKeepsUsage(t *testing.T) {
	const model = "openai/gpt-5.5"
	meta := &qtypes.ResponseRequestMeta{NativeCustom: &qtypes.NativeCustomTools{Definitions: map[string]map[string]any{"patch": {"type": "custom"}}}}
	for _, reason := range []string{"content_filter", "max_output_tokens"} {
		for _, itemClosed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/itemClosed=%v", reason, itemClosed), func(t *testing.T) {
				parts := strings.SplitN(customTestEvents(t, []string{"partial"}), "\n\n", 3)
				wire := parts[0] + "\n\n" + parts[1] + "\n\n"
				if itemClosed {
					wire += "data: " + `{"type":"response.output_item.done","output_index":0,"item":{"type":"custom_tool_call","id":"ctc_123","call_id":"call_xyz","name":"patch","status":"incomplete","input":"partial"}}` + "\n\n"
				}
				wire += fmt.Sprintf("data: "+`{"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":%q},"usage":{"input_tokens":100,"output_tokens":30,"total_tokens":130}}}`+"\n\n", reason)
				var internal, public bytes.Buffer
				if err := translateNativeResponsesStream(strings.NewReader(wire), &internal, meta.NativeCustom); err != nil {
					t.Fatal(err)
				}
				result, err := adapter.CollectAnthropicTextStrict(bytes.NewReader(internal.Bytes()))
				if err != nil || result.Usage == nil || result.Usage.InputTokens != 100 || result.Usage.OutputTokens != 30 {
					t.Fatalf("lost provider usage: %+v, %v", result.Usage, err)
				}
				check := func(payload []byte) {
					t.Helper()
					var r struct {
						Status            string
						IncompleteDetails struct{ Reason string } `json:"incomplete_details"`
						Usage             struct {
							Total int `json:"total_tokens"`
						}
						Output []struct{ Type, Status, Input string }
					}
					if err := json.Unmarshal(payload, &r); err != nil {
						t.Fatal(err)
					}
					if r.Status != "incomplete" || r.IncompleteDetails.Reason != reason || r.Usage.Total != 130 || len(r.Output) != 1 || r.Output[0].Type != "custom_tool_call" || r.Output[0].Input != "partial" || r.Output[0].Status != "incomplete" {
						t.Fatalf("wrong truncated response: %+v", r)
					}
				}
				if err := adapter.WriteResponsesResponse(&public, "resp_test", model, "", result.ToolCalls, result.FinishReason, 100, 30, result.Usage, 1, nil, meta); err != nil {
					t.Fatal(err)
				}
				check(public.Bytes())
				public.Reset()
				settlements := 0
				control := &adapter.StreamControl{ExposeResponsesUsage: true, BeforeTerminal: func(term adapter.StreamTerminal) error {
					settlements++
					if term.Result.Usage == nil || term.Result.Usage.InputTokens != 100 || term.Result.Usage.OutputTokens != 30 {
						t.Fatal("lost terminal settlement usage")
					}
					return term.Emit()
				}}
				if _, err := adapter.TransformResponsesStreamControlled(bytes.NewReader(internal.Bytes()), &public, "resp_test", model, 100, nil, meta, nil, control); err != nil {
					t.Fatal(err)
				}
				var terminals int
				for _, line := range strings.Split(public.String(), "\n") {
					if !strings.HasPrefix(line, "data: {") {
						continue
					}
					var e struct {
						Type     string
						Response json.RawMessage
					}
					if err := json.Unmarshal([]byte(line[6:]), &e); err != nil {
						t.Fatal(err)
					}
					switch e.Type {
					case "response.incomplete":
						terminals++
						check(e.Response)
					case "response.completed", "response.custom_tool_call_input.done":
						t.Fatalf("false completion: %s", e.Type)
					}
				}
				if settlements != 1 || terminals != 1 || strings.Count(public.String(), "data: [DONE]") != 1 {
					t.Fatal("wrong terminal count")
				}
			})
		}
	}
}

func TestNativeCustomRejectsChangedReplayIDs(t *testing.T) {
	for _, meta := range []*qtypes.NativeCustomTools{{CallIDs: map[string]bool{"original": true}}, {OutputIDs: map[string]bool{"original": true}}} {
		req := openAICompatibleRequest{Model: "gpt-5.5", NativeCustom: meta, Messages: []chatMessage{{Role: "tool", ToolCallID: "rewritten", Content: "ok"}}}
		if _, err := buildOpenAIResponsesRequest(req); err == nil || !strings.Contains(err.Error(), "history IDs") {
			t.Fatalf("missing or wrong rejection: %v", err)
		}
	}
}

func TestNativeCustomDeltaArrivesBeforeUpstreamFinishes(t *testing.T) {
	up, send := io.Pipe()
	events, translated := io.Pipe()
	public, writer := io.Pipe()
	t.Cleanup(func() {
		up.Close()
		send.Close()
		events.Close()
		translated.Close()
		public.Close()
		writer.Close()
	})
	meta := &qtypes.ResponseRequestMeta{NativeCustom: &qtypes.NativeCustomTools{Definitions: map[string]map[string]any{"patch": {"type": "custom"}}}}
	go func() { translated.CloseWithError(translateNativeResponsesStream(up, translated, meta.NativeCustom)) }()
	go func() {
		_, err := adapter.TransformResponsesStream(events, writer, "resp_test", "openai/gpt-5.5", 100, nil, meta)
		writer.CloseWithError(err)
	}()
	first := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		s := bufio.NewScanner(public)
		for s.Scan() {
			if strings.HasPrefix(s.Text(), "data: ") && strings.Contains(s.Text(), `"delta":"early"`) && strings.Contains(s.Text(), "response.custom_tool_call_input.delta") {
				first <- struct{}{}
			}
		}
		done <- s.Err()
	}()
	fixture := customTestEvents(t, []string{"early", " and late"})
	lines := strings.SplitN(fixture, "\n\n", 3)
	if _, err := io.WriteString(send, lines[0]+"\n\n"+lines[1]+"\n\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first:
	case <-time.After(3 * time.Second):
		t.Fatal("client did not receive a custom tool delta before upstream completion")
	}
	if _, err := io.WriteString(send, lines[2]); err != nil {
		t.Fatal(err)
	}
	send.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
