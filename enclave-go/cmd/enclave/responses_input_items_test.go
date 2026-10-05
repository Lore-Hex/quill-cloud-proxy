package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestResponsesInputItemsTokenEndpoint(t *testing.T) {
	// Exercise the handler in memory: no gateway or provider calls are needed.
	serve := func(input string) (int, string) {
		t.Helper()
		var out bytes.Buffer
		serveResponsesInputTokens(&out, []byte(`{"model":"m","input":`+input+`}`))
		response, err := http.ReadResponse(bufio.NewReader(&out), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(body)
	}
	t.Run("replayed history counts like equivalent chat history", func(t *testing.T) {
		status, body := serve(`[
			{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"thinking"}]},
			{"type":"web_search_call","id":"ws_1","action":{"type":"search","query":"weather","sources":[{"type":"url","url":"https://example.test/weather"}]}},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"It is sunny.","annotations":[{"type":"url_citation","url":"https://example.test/weather","title":"Weather","start_index":0,"end_index":12}]}]},
			{"type":"custom_tool_call","call_id":"c1","name":"apply_patch","input":"x"},
			{"type":"custom_tool_call_output","call_id":"c1","output":"ok"},
			{"role":"user","content":"Continue."}
		]`)
		if status != 200 {
			t.Fatalf("replay status = %d, body = %s", status, body)
		}
		baselineStatus, baseline := serve(`[
			{"role":"assistant","content":"It is sunny."},
			{"type":"function_call","call_id":"c1","name":"apply_patch","arguments":"{\"input\":\"x\"}"},
			{"type":"function_call_output","call_id":"c1","output":"ok"},
			{"role":"user","content":"Continue."}
		]`)
		if baselineStatus != 200 || body != baseline {
			t.Fatalf("replayed count = %s, equivalent history = %d %s", body, baselineStatus, baseline)
		}
		var count struct {
			Object      string `json:"object"`
			InputTokens int    `json:"input_tokens"`
		}
		if err := json.Unmarshal([]byte(body), &count); err != nil || count.Object != "response.input_tokens" || count.InputTokens <= 0 {
			t.Fatalf("invalid token count: %s (%v)", body, err)
		}
	})
	for _, tc := range []struct {
		name, input, want string
		status            int
	}{
		{"reference", `[{"type":"item_reference","id":"msg_123"}]`, `"param":"input[0].item_reference"`, 501},
		{"custom missing id", `[{"type":"custom_tool_call","name":"apply_patch"}]`, `"param":"input[0].call_id"`, 400},
		{"reasoning only", `[{"type":"reasoning","summary":[]}]`, `"message":"input must contain text"`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := serve(tc.input)
			if status != tc.status || !strings.Contains(body, tc.want) {
				t.Fatalf("status = %d, body = %s, want %d containing %s", status, body, tc.status, tc.want)
			}
		})
	}
}
