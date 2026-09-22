package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func responsesTestTool() []any {
	return []any{map[string]any{"type": "function", "function": map[string]any{
		"name": "weather", "parameters": map[string]any{"type": "object", "properties": map[string]any{"city": map[string]any{"type": "string"}}},
	}}}
}

func responsesTestSSE(events ...string) string {
	return "data: " + strings.Join(events, "\n\ndata: ") + "\n\n"
}

const responsesTestTerminal = `{"type":"response.completed","response":{"service_tier":"default","usage":{"input_tokens":100,"input_tokens_details":{"cached_tokens":60},"output_tokens":30,"output_tokens_details":{"reasoning_tokens":20},"total_tokens":130}}}`

func TestOpenAIResponsesRoutingIsScoped(t *testing.T) {
	for _, model := range []string{"gpt-6-sol", "gpt-6-luna", "gpt-6-astra", "openai/gpt-6-sol"} {
		for _, effort := range []string{"", "none", "low", "high", "max"} {
			req := openAICompatibleRequest{Model: model, Tools: responsesTestTool(), ReasoningEffort: effort}
			if !useOpenAIResponses("openai", req) {
				t.Fatalf("missing native Responses route: %s/%s", model, effort)
			}
			for _, provider := range []string{"azure", "deepinfra", "user-model"} {
				if useOpenAIResponses(provider, req) {
					t.Fatalf("changed unverified provider %s", provider)
				}
			}
		}
		if useOpenAIResponses("openai", openAICompatibleRequest{Model: model}) {
			t.Fatal("plain chat changed")
		}
		if !useOpenAIResponses("openai", openAICompatibleRequest{Model: model, Messages: []chatMessage{{Role: "tool"}}}) {
			t.Fatal("tool history without new tools must remain on Responses")
		}
	}
	for _, model := range []string{"gpt-5.6-sol", "gpt-6-sol-pro", "gpt-7", "gpt-oss-120b"} {
		if useOpenAIResponses("openai", openAICompatibleRequest{Model: model, Tools: responsesTestTool()}) {
			t.Fatalf("changed unverified model %s", model)
		}
	}
}

func TestOpenAIResponsesRequestAndToolContinuation(t *testing.T) {
	parallel := false
	req := openAICompatibleRequest{
		Model: "gpt-6-sol", Stream: true, MaxCompletionTokens: 123,
		ReasoningEffort: "high", ServiceTier: "default", PromptCacheKey: "cache-scope",
		Tools: responsesTestTool(), ParallelToolCalls: &parallel,
		ToolChoice:     map[string]any{"type": "function", "function": map[string]any{"name": "weather"}},
		ResponseFormat: map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "answer", "schema": map[string]any{"type": "object"}, "strict": true}},
		Messages: []chatMessage{
			{Role: "system", Content: "system prompt"},
			{Role: "user", Content: []any{map[string]any{"type": "text", "text": "Paris"}, map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64,abc", "detail": "low"}}}},
			{Role: "assistant", Content: "", ToolCalls: []map[string]any{{"id": "call_weather", "function": map[string]any{"name": "weather", "arguments": `{"city":"Paris"}`}}}},
			{Role: "tool", ToolCallID: "call_weather", Content: "Sunny"},
		},
	}
	got, err := buildOpenAIResponsesRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if got["store"] != false || got["max_output_tokens"] != 123 || got["prompt_cache_key"] != "cache-scope" || got["service_tier"] != "default" || got["parallel_tool_calls"] != false {
		t.Fatalf("request options lost: %#v", got)
	}
	if got["reasoning"].(map[string]any)["effort"] != "high" {
		t.Fatal("reasoning downgraded")
	}
	for _, field := range []string{"messages", "thinking", "max_tokens", "max_completion_tokens", "stream_options", "reasoning_effort", "response_format"} {
		if _, exists := got[field]; exists {
			t.Errorf("chat field leaked: %s", field)
		}
	}
	input := got["input"].([]any)
	if len(input) != 4 || input[0].(map[string]any)["role"] != "system" || input[2].(map[string]any)["call_id"] != "call_weather" || input[3].(map[string]any)["output"] != "Sunny" {
		t.Fatalf("tool history corrupted: %#v", input)
	}
	image := input[1].(map[string]any)["content"].([]any)[1].(map[string]any)
	if image["type"] != "input_image" || image["detail"] != "low" {
		t.Fatalf("image corrupted: %#v", image)
	}
	tool := got["tools"].([]any)[0].(map[string]any)
	if tool["strict"] != false || tool["name"] != "weather" || tool["type"] != "function" {
		t.Fatalf("tool semantics changed: %#v", tool)
	}
	if _, leaked := req.Tools[0].(map[string]any)["function"].(map[string]any)["strict"]; leaked {
		t.Fatal("mutated original tool schema")
	}
	if got["tool_choice"].(map[string]any)["name"] != "weather" {
		t.Fatal("named tool choice lost")
	}
	if got["text"].(map[string]any)["format"].(map[string]any)["type"] != "json_schema" {
		t.Fatal("structured output lost")
	}
}

func TestOpenAIResponsesWireForChatAndResponses(t *testing.T) {
	for _, model := range []string{"openai/gpt-6-sol", "openai/gpt-6-luna"} {
		for _, publicResponses := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/responses=%t", model, publicResponses), func(t *testing.T) {
				limit := 256
				req := &qtypes.OpenAIChatRequest{Model: model, Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "weather"}}, Tools: responsesTestTool(), Reasoning: map[string]any{"effort": "high"}, MaxTokens: &limit}
				if publicResponses {
					var err error
					req, err = adapter.ResponsesToChat(&qtypes.OpenAIResponsesRequest{Model: model, Input: "weather", Tools: []any{map[string]any{"type": "function", "name": "weather", "parameters": map[string]any{"type": "object", "properties": map[string]any{}}}}, Reasoning: map[string]any{"effort": "high"}, MaxOutputTokens: &limit})
					if err != nil {
						t.Fatal(err)
					}
				}
				body, err := adapter.ToAnthropic(req, model)
				if err != nil {
					t.Fatal(err)
				}
				client := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer test-key" {
						t.Fatalf("wrong request: %s", r.URL.Path)
					}
					var wire map[string]any
					if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
						t.Fatal(err)
					}
					if wire["store"] != false || wire["max_output_tokens"] != float64(limit) || wire["reasoning"].(map[string]any)["effort"] != "high" {
						t.Fatalf("wire lost contract: %#v", wire)
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(responsesTestSSE(responsesTestTerminal)))}, nil
				})}
				var out bytes.Buffer
				if err := invokeOpenAICompatibleStreamingWithClient(context.Background(), client, "openai", "https://api.openai.test/v1", "test-key", req, body, &out, strings.TrimPrefix(model, "openai/")); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestOpenAIResponsesStreamPreservesToolsReasoningAndUsage(t *testing.T) {
	wire := responsesTestSSE(
		`{"type":"response.reasoning_summary_text.delta","delta":"summary"}`,
		`{"type":"response.output_text.delta","delta":"answer"}`,
		`{"type":"response.output_item.added","output_index":2,"item":{"type":"function_call","call_id":"call_a","name":"weather"}}`,
		`{"type":"response.output_item.added","output_index":3,"item":{"type":"function_call","call_id":"call_b","name":"weather"}}`,
		`{"type":"response.function_call_arguments.delta","output_index":2,"delta":"{\"city\":"}`,
		`{"type":"response.function_call_arguments.delta","output_index":3,"delta":"{\"city\":\"London\"}"}`,
		`{"type":"response.function_call_arguments.delta","output_index":2,"delta":"\"Paris\"}"}`,
		`{"type":"response.output_item.done","output_index":3,"item":{"type":"function_call"}}`,
		`{"type":"response.output_item.done","output_index":2,"item":{"type":"function_call"}}`,
		responsesTestTerminal,
	)
	var native bytes.Buffer
	if err := translateOpenAIResponsesStream(strings.NewReader(wire), &native); err != nil {
		t.Fatal(err)
	}
	for _, surface := range []string{"json", "chat_stream", "responses_stream"} {
		t.Run(surface, func(t *testing.T) {
			var result adapter.StreamResult
			var err error
			var out bytes.Buffer
			switch surface {
			case "json":
				result, err = adapter.CollectAnthropicText(strings.NewReader(native.String()))
			case "chat_stream":
				result, err = adapter.TransformStreamCaptureWithOptions(strings.NewReader(native.String()), &out, "id", "openai/gpt-6-sol", true)
			case "responses_stream":
				result, err = adapter.TransformResponsesStream(strings.NewReader(native.String()), &out, "id", "openai/gpt-6-sol", 100, nil, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Text != "answer" || adapter.JoinThinking(result.Thinking) != "summary" || len(result.ToolCalls) != 2 {
				t.Fatalf("lost content or tools: %#v", result)
			}
			if result.ToolCalls[0].ID != "call_a" || result.ToolCalls[0].Arguments != `{"city":"Paris"}` || result.ToolCalls[1].ID != "call_b" {
				t.Fatalf("tool calls changed: %#v", result.ToolCalls)
			}
			if result.Usage == nil || result.Usage.InputTokens != 100 || result.Usage.OutputTokens != 30 || result.Usage.CacheReadInputTokens != 60 || result.Usage.ReasoningTokens != 20 || result.Usage.ServiceTier != "default" {
				t.Fatalf("accounting changed: %#v", result.Usage)
			}
		})
	}
}

func TestOpenAIResponsesRejectsBrokenStreams(t *testing.T) {
	for _, wire := range []string{
		"", "data: [DONE]\n\n", "data: {invalid}\n\n",
		responsesTestSSE(`{"type":"response.completed","response":{}}`),
		responsesTestSSE(`{"type":"response.failed","response":{"error":{"message":"PRIVATE"}}}`),
		responsesTestSSE(`{"type":"error","message":"PRIVATE"}`),
		responsesTestSSE(`{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{}"}`),
		strings.Replace(responsesTestSSE(responsesTestTerminal), `"total_tokens":130`, `"total_tokens":131`, 1),
		strings.Replace(responsesTestSSE(responsesTestTerminal), `"cached_tokens":60`, `"cached_tokens":101`, 1),
		strings.Replace(responsesTestSSE(responsesTestTerminal), `"reasoning_tokens":20`, `"reasoning_tokens":31`, 1),
	} {
		var out bytes.Buffer
		err := translateOpenAIResponsesStream(strings.NewReader(wire), &out)
		if err == nil || strings.Contains(out.String(), "message_stop") || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("accepted broken/private stream: error=%v output=%s", err, out.String())
		}
	}
}

func TestOpenAIResponsesTruncationAndWriterError(t *testing.T) {
	wire := strings.Replace(responsesTestTerminal, "response.completed", "response.incomplete", 1)
	wire = strings.Replace(wire, `"service_tier":`, `"incomplete_details":{"reason":"max_output_tokens"},"service_tier":`, 1)
	var out bytes.Buffer
	if err := translateOpenAIResponsesStream(strings.NewReader(responsesTestSSE(wire)), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"stop_reason":"max_tokens"`) {
		t.Fatalf("truncation reported as success: %s", out.String())
	}
	want := errors.New("closed writer")
	if err := translateOpenAIResponsesStream(strings.NewReader(responsesTestSSE(responsesTestTerminal)), responsesFailWriter{want}); !errors.Is(err, want) {
		t.Fatalf("writer error lost: %v", err)
	}
}

type responsesFailWriter struct{ err error }

func (w responsesFailWriter) Write([]byte) (int, error) { return 0, w.err }

func TestOpenAIResponsesPreservesCancellationAndHTTPFailure(t *testing.T) {
	req := &qtypes.OpenAIChatRequest{Model: "openai/gpt-6-sol", Tools: responsesTestTool()}
	body := &qtypes.AnthropicMessagesRequest{}
	for _, status := range []int{400, 429, 503} {
		client := &http.Client{Transport: byokRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("provider failure"))}, nil
		})}
		var out bytes.Buffer
		err := invokeOpenAICompatibleStreamingWithClient(t.Context(), client, "openai", "https://api.openai.test/v1", "key", req, body, &out, "gpt-6-sol")
		if got, ok := HTTPStatusFromError(err); !ok || got != status || out.Len() != 0 {
			t.Fatalf("HTTP error changed: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	client := &http.Client{Transport: byokRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, r.Context().Err()
	})}
	err := invokeOpenAICompatibleStreamingWithClient(ctx, client, "openai", "https://api.openai.test/v1", "key", req, body, io.Discard, "gpt-6-sol")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestOpenAIResponsesRejectsUnsupportedOptionsWithoutDroppingThem(t *testing.T) {
	req := openAICompatibleRequest{Model: "gpt-6-sol", Stop: "STOP"}
	if _, err := buildOpenAIResponsesRequest(req); err == nil {
		t.Fatal("silently ignored stop")
	}
	req.Stop = nil
	req.Tools = []any{map[string]any{"type": "web_search"}}
	if _, err := buildOpenAIResponsesRequest(req); err == nil {
		t.Fatal("leaked unbudgeted hosted tool")
	}
}

// Opt-in, bounded paid canary. No credentials, prompts, or outputs are logged.
func TestOpenAIResponsesLiveToolLoop(t *testing.T) {
	if os.Getenv("TR_TEST_OPENAI_RESPONSES") != "1" {
		t.Skip("set TR_TEST_OPENAI_RESPONSES=1 and OPENAI_API_KEY for paid native canary")
	}
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		t.Fatal("missing OPENAI_API_KEY")
	}
	for _, model := range []string{"gpt-6-sol", "gpt-6-luna"} {
		t.Run(model, func(t *testing.T) {
			limit := 512
			req := &qtypes.OpenAIChatRequest{
				Model: model, MaxTokens: &limit, ReasoningEffort: "high", Tools: responsesTestTool(),
				Messages: []qtypes.OpenAIChatMessage{{Role: "user", Content: "Call weather for Paris. After receiving the tool result, reply exactly PONG."}},
			}
			for turn := 0; turn < 2; turn++ {
				body, err := adapter.ToAnthropic(req, model)
				if err != nil {
					t.Fatal(err)
				}
				var out bytes.Buffer
				err = InvokeOpenAICompatibleStreaming(t.Context(), "openai", "https://api.openai.com/v1", key, req, body, &out, model)
				if err != nil {
					t.Fatalf("native canary failed: %v", err)
				}
				result, err := adapter.CollectAnthropicText(strings.NewReader(out.String()))
				if err != nil || result.Usage == nil || result.Usage.InputTokens <= 0 || result.Usage.OutputTokens <= 0 {
					t.Fatal("missing native usage or malformed response")
				}
				t.Logf("turn=%d input=%d output=%d reasoning=%d tools=%d", turn, result.Usage.InputTokens, result.Usage.OutputTokens, result.Usage.ReasoningTokens, len(result.ToolCalls))
				if turn == 0 {
					if len(result.ToolCalls) != 1 || result.ToolCalls[0].Name != "weather" {
						t.Fatal("missing function call")
					}
					call := result.ToolCalls[0]
					req.Messages = append(req.Messages,
						qtypes.OpenAIChatMessage{Role: "assistant", Content: result.Text, ToolCalls: []qtypes.OpenAIToolCall{{ID: call.ID, Type: "function", Function: qtypes.OpenAIToolFunction{Name: call.Name, Arguments: call.Arguments}}}},
						qtypes.OpenAIChatMessage{Role: "tool", ToolCallID: call.ID, Content: "Sunny"},
					)
				} else if strings.TrimSpace(result.Text) != "PONG" || len(result.ToolCalls) != 0 {
					t.Fatal("tool continuation failed")
				}
			}
		})
	}
}
