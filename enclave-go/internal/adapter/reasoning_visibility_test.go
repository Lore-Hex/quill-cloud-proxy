package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestChatReasoningVisibilityCompatibility(t *testing.T) {
	for _, body := range []string{
		`{"include_reasoning":true}`,
		`{"include_reasoning":false}`,
		`{"include_reasoning":null}`,
		`{"reasoning":{"exclude":true}}`,
	} {
		t.Run(body, func(t *testing.T) {
			validation, err := ValidateChatRequestFields(rawChatRequest(t, body))
			if err != nil {
				t.Fatal(err)
			}
			if len(validation.RequestedParameters) != 0 {
				t.Fatalf("output visibility must not require a provider capability: %v", validation.RequestedParameters)
			}
		})
	}
}

func TestReasoningVisibilityNormalizationAndPrecedence(t *testing.T) {
	for _, tc := range []struct {
		body     string
		exclude  bool
		upstream string
	}{
		{`{}`, false, `null`},
		{`{"include_reasoning":false}`, true, `null`},
		{`{"include_reasoning":true}`, false, `null`},
		{`{"include_reasoning":true,"reasoning":{"exclude":true,"effort":"high"}}`, true, `{"effort":"high"}`},
		{`{"include_reasoning":false,"reasoning":{"exclude":false,"enabled":false}}`, false, `{"enabled":false}`},
		{`{"reasoning":{"exclude":true}}`, true, `null`},
	} {
		t.Run(tc.body, func(t *testing.T) {
			validation, err := ValidateChatRequestFields(rawChatRequest(t, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			var req types.OpenAIChatRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatal(err)
			}
			original, _ := json.Marshal(req.Reasoning)
			shared := req.Reasoning
			ConfigureReasoningVisibility(&req, validation.ExcludeReasoning)
			wire, _ := json.Marshal(req.Reasoning)
			if req.ExcludeReasoning != tc.exclude || string(wire) != tc.upstream {
				t.Fatalf("exclude=%v reasoning=%s", req.ExcludeReasoning, wire)
			}
			after, _ := json.Marshal(shared)
			if !bytes.Equal(original, after) {
				t.Fatal("mutated shared provider reasoning config")
			}
		})
	}
}

const visibilityStream = `event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"private-thought"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"private-signature"}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"42"}}

event: content_block_start
data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"call1","name":"lookup","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"reasoning\":\"tool-data\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":2}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"input_tokens":7,"output_tokens":900,"reasoning_tokens":850}}

event: message_stop
data: {"type":"message_stop"}

`

func TestExcludedReasoningPreservesCaptureMeteringUsageAndTools(t *testing.T) {
	for _, responses := range []bool{false, true} {
		for _, exclude := range []bool{false, true} {
			var out bytes.Buffer
			metered := ""
			settlements := 0
			control := &StreamControl{
				ExcludeReasoning: exclude,
				BeforeSlice: func(delta StreamDelta) error {
					if delta.Type == "thinking_delta" {
						metered += delta.Text
					}
					return nil
				},
				BeforeTerminal: func(terminal StreamTerminal) error {
					settlements++
					if terminal.Result.Usage.OutputTokens != 900 {
						t.Fatal("settlement lost reasoning usage")
					}
					return terminal.Emit()
				},
			}
			var result StreamResult
			var err error
			if responses {
				result, err = TransformResponsesStreamControlled(strings.NewReader(visibilityStream), &out, "resp1", "model", 7, nil, nil, nil, control)
			} else {
				result, err = TransformStreamCaptureControlled(strings.NewReader(visibilityStream), &out, "chat1", "model", true, nil, nil, control)
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "private-thought") == exclude {
				t.Fatalf("responses=%v exclude=%v: %s", responses, exclude, out.String())
			}
			if metered != "private-thought" || settlements != 1 || result.Usage.ReasoningTokens != 850 || result.Usage.OutputTokens != 900 {
				t.Fatalf("capture or billing changed: %q settlements=%d result=%+v", metered, settlements, result)
			}
			if len(result.Thinking) != 1 || result.Thinking[0].Text != "private-thought" || result.Thinking[0].Signature != "private-signature" {
				t.Fatalf("thinking lost: %+v", result)
			}
			if len(result.ToolCalls) != 1 || result.ToolCalls[0].Arguments != `{"reasoning":"tool-data"}` {
				t.Fatalf("tools changed: %+v", result.ToolCalls)
			}
			if !strings.Contains(out.String(), "tool-data") || !strings.Contains(out.String(), "data: [DONE]") {
				t.Fatalf("broken stream: %s", out.String())
			}
		}
	}
}

func TestVisibleThinkingJSONPreservesUsage(t *testing.T) {
	req := &types.OpenAIChatRequest{ExcludeReasoning: true}
	var out bytes.Buffer
	err := WriteChatCompletionResponse(&out, "id", "model", "42", VisibleThinking(req, []ThinkingBlock{{Text: "private-thought"}}), nil, 7, 900, &StreamUsage{InputTokens: 7, OutputTokens: 900, ReasoningTokens: 850}, 1, "stop")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "private-thought") || strings.Contains(out.String(), `"reasoning_content"`) {
		t.Fatal(out.String())
	}
	if !strings.Contains(out.String(), `"reasoning_tokens":850`) || !strings.Contains(out.String(), `"completion_tokens":900`) {
		t.Fatal(out.String())
	}
}

func TestChatReasoningVisibilityRejectsMalformedValues(t *testing.T) {
	for _, tc := range []struct{ body, parameter string }{
		{`{"include_reasoning":"false"}`, "include_reasoning"},
		{`{"include_reasoning":1}`, "include_reasoning"},
		{`{"include_reasoning":{}}`, "include_reasoning"},
		{`{"reasoning":{"exclude":"true"}}`, "reasoning.exclude"},
		{`{"reasoning":{"exclude":[]}}`, "reasoning.exclude"},
	} {
		t.Run(tc.body, func(t *testing.T) {
			_, err := ValidateChatRequestFields(rawChatRequest(t, tc.body))
			assertRequestFieldError(t, err, 400, tc.parameter)
		})
	}
}
