package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteResponsesResponseReportsLengthStopAsIncomplete(t *testing.T) {
	var out bytes.Buffer
	if err := WriteResponsesResponse(&out, "resp_len", "anthropic/claude-fable-5.1", "", nil, "length", 12, 16000, nil, 123, nil, nil); err != nil {
		t.Fatalf("WriteResponsesResponse: %v", err)
	}
	var payload struct {
		Status            string         `json:"status"`
		CompletedAt       *int64         `json:"completed_at"`
		IncompleteDetails map[string]any `json:"incomplete_details"`
		Output            []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"output"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Status != "incomplete" || payload.IncompleteDetails["reason"] != "max_output_tokens" {
		t.Fatalf("status=%q incomplete_details=%v, want incomplete/max_output_tokens", payload.Status, payload.IncompleteDetails)
	}
	if payload.CompletedAt != nil {
		t.Fatalf("completed_at = %d, want null on an incomplete response", *payload.CompletedAt)
	}
	if len(payload.Output) != 1 || payload.Output[0].Status != "incomplete" {
		t.Fatalf("output = %+v, want one incomplete message", payload.Output)
	}
	if payload.Usage["output_tokens"] != float64(16000) {
		t.Fatalf("usage = %v, want the billed output tokens kept", payload.Usage)
	}
}

func TestWriteResponsesResponseKeepsNaturalStopCompleted(t *testing.T) {
	var out bytes.Buffer
	if err := WriteResponsesResponse(&out, "resp_stop", "anthropic/claude-fable-5.1", "done", nil, "stop", 12, 3, nil, 123, nil, nil); err != nil {
		t.Fatalf("WriteResponsesResponse: %v", err)
	}
	if !strings.Contains(out.String(), `"status":"completed"`) || !strings.Contains(out.String(), `"incomplete_details":null`) {
		t.Fatalf("natural stop should stay completed: %s", out.String())
	}
}

func TestTransformResponsesStreamReportsLengthStopAsIncomplete(t *testing.T) {
	stream := strings.NewReader(strings.Join([]string{
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"cut off mid"}}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":40}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n"))
	var out bytes.Buffer
	result, err := TransformResponsesStream(stream, &out, "resp_test", "anthropic/claude-fable-5.1", 10, nil, nil)
	if err != nil {
		t.Fatalf("TransformResponsesStream: %v", err)
	}
	if result.FinishReason != "length" {
		t.Fatalf("finish reason = %q, want length", result.FinishReason)
	}
	body := out.String()
	if strings.Contains(body, "response.completed") {
		t.Fatalf("length stop must not emit response.completed: %s", body)
	}
	for _, want := range []string{
		`event: response.incomplete`,
		`"status":"incomplete"`,
		`"incomplete_details":{"reason":"max_output_tokens"}`,
		`"text":"cut off mid"`,
		`"completed_at":null`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stream missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, `"type":"message","status":"completed"`) || strings.Contains(body, `"status":"completed","type":"message"`) {
		t.Fatalf("message item still marked completed: %s", body)
	}
}

func TestTransformResponsesStreamRewritesClientCallIDsOnly(t *testing.T) {
	stream := strings.NewReader(strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"web_search"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":4}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n"))
	var out bytes.Buffer
	control := &StreamControl{ToolCallID: func(id string) string { return "pinned_" + id }}
	result, err := TransformResponsesStreamControlled(stream, &out, "resp_test", "m", 10, nil, nil, nil, control)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ToolCalls) != 1 || result.ToolCalls[0].CallID != "pinned_toolu_01" || result.ToolCalls[0].ID != "toolu_01" {
		t.Fatalf("tool calls = %+v", result.ToolCalls)
	}
	body := out.String()
	if strings.Count(body, `"call_id":"pinned_toolu_01"`) < 2 || strings.Contains(body, `"call_id":"toolu_01"`) {
		t.Fatalf("client must see only the rewritten call_id in added and done events: %s", body)
	}
}
