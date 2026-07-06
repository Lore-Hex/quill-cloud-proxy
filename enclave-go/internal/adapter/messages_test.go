package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestMessagesToAnthropicValidatesAndPreservesNativeShape(t *testing.T) {
	topK := 40
	req := &AnthropicNativeRequest{
		Model: "anthropic/claude-haiku-4.5",
		Messages: []types.AnthropicMessage{
			{Role: "user", Content: []any{map[string]any{
				"type":          "text",
				"text":          "hello",
				"cache_control": map[string]any{"type": "ephemeral"},
			}}},
		},
		System: []any{map[string]any{
			"type":          "text",
			"text":          "be brief",
			"cache_control": map[string]any{"type": "ephemeral"},
		}},
		MaxTokens:     128,
		StopSequences: []string{"END"},
		TopK:          &topK,
	}
	out, err := MessagesToAnthropic(req)
	if err != nil {
		t.Fatalf("MessagesToAnthropic: %v", err)
	}
	if !out.NativeContent || !out.MaxTokensExplicit {
		t.Fatalf("flags = native:%v explicit:%v, want true/true", out.NativeContent, out.MaxTokensExplicit)
	}
	if out.System != "be brief" {
		t.Fatalf("flattened system = %q", out.System)
	}
	if out.SystemRaw == nil {
		t.Fatal("SystemRaw dropped — cache_control blocks would be lost")
	}
	if len(out.StopSequences) != 1 || out.StopSequences[0] != "END" {
		t.Fatalf("stop_sequences = %#v", out.StopSequences)
	}
	if out.TopK == nil || *out.TopK != 40 {
		t.Fatalf("top_k = %#v, want 40", out.TopK)
	}
	// Content blocks must be byte-identical pass-through (cache_control intact).
	blocks := out.Messages[0].Content.([]any)
	if _, ok := blocks[0].(map[string]any)["cache_control"]; !ok {
		t.Fatalf("cache_control stripped from content: %#v", blocks[0])
	}

	for _, bad := range []*AnthropicNativeRequest{
		{Model: "", Messages: req.Messages, MaxTokens: 16},
		{Model: "m", Messages: nil, MaxTokens: 16},
		{Model: "m", Messages: req.Messages, MaxTokens: 0},
		{Model: "m", Messages: []types.AnthropicMessage{{Role: "system", Content: "x"}}, MaxTokens: 16},
	} {
		if _, err := MessagesToAnthropic(bad); err == nil {
			t.Fatalf("invalid request accepted: %#v", bad)
		}
	}
}

func TestMessagesToAnthropicForwardsOutputConfig(t *testing.T) {
	// opus-4.7+ rejects thinking.type=enabled+budget_tokens and requires
	// thinking.type=adaptive PLUS output_config.effort. The gateway forwarded
	// `thinking` but dropped `output_config`, so adaptive arrived without its
	// effort directive (minimal thinking). output_config must be carried through.
	req := &AnthropicNativeRequest{
		Model:     "anthropic/claude-opus-4.7",
		MaxTokens: 256,
		Messages: []types.AnthropicMessage{
			{Role: "user", Content: "hi"},
		},
		Thinking:     map[string]any{"type": "adaptive"},
		OutputConfig: map[string]any{"effort": "xhigh"},
	}
	out, err := MessagesToAnthropic(req)
	if err != nil {
		t.Fatalf("MessagesToAnthropic: %v", err)
	}
	oc, ok := out.OutputConfig.(map[string]any)
	if !ok {
		t.Fatalf("output_config dropped: %#v", out.OutputConfig)
	}
	if oc["effort"] != "xhigh" {
		t.Fatalf("output_config.effort = %v, want xhigh", oc["effort"])
	}
	if th, _ := out.Thinking.(map[string]any); th["type"] != "adaptive" {
		t.Fatalf("thinking not preserved: %#v", out.Thinking)
	}
}

func TestMessagesToAnthropicStripsEmptyTextBlocks(t *testing.T) {
	// Repro: a multi-turn tool loop replays a near-empty assistant turn (a lone
	// whitespace token). Anthropic 400s on empty/whitespace text blocks, which
	// the gateway surfaced as a 502 and killed the conversation. The sanitizer
	// must drop the empty text block while keeping tool_use / non-empty text /
	// cache_control intact.
	req := &AnthropicNativeRequest{
		Model:     "anthropic/claude-opus-4.7",
		MaxTokens: 256,
		Messages: []types.AnthropicMessage{
			{Role: "user", Content: "explore the target"},
			// assistant turn: real reasoning + a tool call (must be preserved)
			{Role: "assistant", Content: []any{
				map[string]any{"type": "text", "text": "Let me list the dir."},
				map[string]any{"type": "tool_use", "id": "tu_1", "name": "exec", "input": map[string]any{"cmd": "ls"}},
			}},
			{Role: "user", Content: []any{
				map[string]any{"type": "tool_result", "tool_use_id": "tu_1", "content": "a.js\nb.js"},
			}},
			// degenerate near-empty assistant turn: empty text + whitespace text
			{Role: "assistant", Content: []any{
				map[string]any{"type": "text", "text": ""},
				map[string]any{"type": "text", "text": "  \n"},
			}},
			{Role: "user", Content: "continue"},
		},
	}
	out, err := MessagesToAnthropic(req)
	if err != nil {
		t.Fatalf("MessagesToAnthropic: %v", err)
	}
	// assistant turn with real content is untouched (text + tool_use kept).
	a1 := out.Messages[1].Content.([]any)
	if len(a1) != 2 {
		t.Fatalf("real assistant turn altered: %#v", a1)
	}
	if a1[1].(map[string]any)["type"] != "tool_use" {
		t.Fatalf("tool_use dropped: %#v", a1)
	}
	// tool_result message untouched.
	if out.Messages[2].Content.([]any)[0].(map[string]any)["type"] != "tool_result" {
		t.Fatalf("tool_result dropped: %#v", out.Messages[2].Content)
	}
	// degenerate assistant turn: both empty/whitespace text blocks stripped -> [].
	a2, ok := out.Messages[3].Content.([]any)
	if !ok {
		t.Fatalf("degenerate turn content type changed: %#v", out.Messages[3].Content)
	}
	if len(a2) != 0 {
		t.Fatalf("empty text blocks not stripped: %#v", a2)
	}
	// the original request must not be mutated (sanitizer works on a copy).
	if len(req.Messages[3].Content.([]any)) != 2 {
		t.Fatalf("sanitizer mutated the input request: %#v", req.Messages[3].Content)
	}
}

func TestMessagesToChatShimConvertsToolsForOpenAIDispatch(t *testing.T) {
	req := &AnthropicNativeRequest{
		Model:     "moonshotai/kimi-k2.6",
		Messages:  []types.AnthropicMessage{{Role: "user", Content: "weather?"}},
		MaxTokens: 64,
		Tools: []types.AnthropicTool{{
			Name:        "get_weather",
			Description: "Get weather.",
			InputSchema: map[string]any{"type": "object"},
		}},
		ToolChoice: &types.AnthropicToolChoice{Type: "tool", Name: "get_weather"},
	}
	shim := MessagesToChatShim(req)
	if shim.MaxTokens == nil || *shim.MaxTokens != 64 {
		t.Fatalf("shim max_tokens = %#v", shim.MaxTokens)
	}
	if len(shim.Tools) != 1 {
		t.Fatalf("shim tools = %#v", shim.Tools)
	}
	tool := shim.Tools[0].(map[string]any)
	fn := tool["function"].(map[string]any)
	if tool["type"] != "function" || fn["name"] != "get_weather" {
		t.Fatalf("bad converted tool: %#v", tool)
	}
	choice := shim.ToolChoice.(map[string]any)
	if choice["function"].(map[string]any)["name"] != "get_weather" {
		t.Fatalf("bad converted tool_choice: %#v", choice)
	}
	// Round-trip sanity: the converted tools survive the OpenAI→Anthropic
	// direction used on non-Anthropic provider paths.
	back, err := AnthropicToolsFromChatTools(shim.Tools)
	if err != nil || len(back) != 1 || back[0].Name != "get_weather" {
		t.Fatalf("round trip = %#v err=%v", back, err)
	}
}

func TestWriteMessagesResponseEnvelope(t *testing.T) {
	var out bytes.Buffer
	err := WriteMessagesResponse(&out, "msg_test", "anthropic/claude-haiku-4.5", StreamResult{
		Text:         "Hello",
		FinishReason: "tool_calls",
		ToolCalls:    []types.ToolCall{{ID: "toolu_1", Name: "get_weather", Arguments: `{"location":"Paris"}`}},
	}, 12, 8)
	if err != nil {
		t.Fatalf("WriteMessagesResponse: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if payload["type"] != "message" || payload["role"] != "assistant" || payload["stop_reason"] != "tool_use" {
		t.Fatalf("bad envelope: %#v", payload)
	}
	content := payload["content"].([]any)
	if len(content) != 2 {
		t.Fatalf("content = %#v", content)
	}
	toolUse := content[1].(map[string]any)
	if toolUse["type"] != "tool_use" || toolUse["name"] != "get_weather" {
		t.Fatalf("tool_use block = %#v", toolUse)
	}
	if toolUse["input"].(map[string]any)["location"] != "Paris" {
		t.Fatalf("tool input = %#v", toolUse["input"])
	}
	usage := payload["usage"].(map[string]any)
	if usage["input_tokens"] != float64(12) || usage["output_tokens"] != float64(8) {
		t.Fatalf("usage = %#v", usage)
	}
}

func TestRelayAnthropicStreamPassthroughPreservesNativeEvents(t *testing.T) {
	native := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_up","type":"message","role":"assistant","content":[],"model":"claude","usage":{"input_tokens":10,"output_tokens":0}}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Hello"}}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	var out bytes.Buffer
	result, err := RelayAnthropicStream(strings.NewReader(native), &out, "msg_local", "model1")
	if err != nil {
		t.Fatalf("RelayAnthropicStream: %v", err)
	}
	// Native streams pass through verbatim — message id stays the
	// upstream one, thinking deltas survive, nothing is injected.
	got := out.String()
	if !strings.Contains(got, `"id":"msg_up"`) || !strings.Contains(got, "thinking_delta") {
		t.Fatalf("passthrough mangled stream: %s", got)
	}
	if strings.Contains(got, "msg_local") {
		t.Fatalf("synthetic framing injected into native stream: %s", got)
	}
	if result.Usage == nil || result.Usage.InputTokens != 10 || result.Usage.OutputTokens != 7 {
		t.Fatalf("usage = %#v", result.Usage)
	}
	if result.Text != "Hello" || result.FinishReason != "stop" {
		t.Fatalf("result = %#v", result)
	}
}

func TestRelayAnthropicStreamSynthesizesFramingAndRemapsIndexes(t *testing.T) {
	// Shape produced by llm/stream_translate.go: bare text deltas at index
	// 0, tool block ALSO at index 0, no message_start / content_block_start
	// for text.
	synthetic := strings.Join([]string{
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call_1","name":"get_weather","input":{}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"input_tokens":5,"output_tokens":9}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	var out bytes.Buffer
	result, err := RelayAnthropicStream(strings.NewReader(synthetic), &out, "msg_local", "kimi-k2.6")
	if err != nil {
		t.Fatalf("RelayAnthropicStream: %v", err)
	}
	got := out.String()
	blocks := strings.Split(strings.TrimSpace(got), "\n\n")
	if !strings.HasPrefix(blocks[0], "event: message_start") || !strings.Contains(blocks[0], `"id":"msg_local"`) {
		t.Fatalf("first event must be injected message_start: %q", blocks[0])
	}
	// Text block must get a synthetic content_block_start at index 0 and
	// the tool block must be remapped off the colliding index 0.
	if !strings.Contains(got, `"content_block":{"text":"","type":"text"}`) && !strings.Contains(got, `"content_block":{"type":"text","text":""}`) {
		t.Fatalf("missing synthetic text content_block_start: %s", got)
	}
	var sawToolStart bool
	for _, block := range blocks {
		if !strings.Contains(block, "content_block_start") || !strings.Contains(block, "tool_use") {
			continue
		}
		sawToolStart = true
		data := block[strings.Index(block, "data: ")+len("data: "):]
		var payload map[string]any
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			t.Fatalf("decode tool start: %v", err)
		}
		if payload["index"] != float64(1) {
			t.Fatalf("tool block index = %#v, want remapped 1", payload["index"])
		}
	}
	if !sawToolStart {
		t.Fatalf("tool content_block_start missing: %s", got)
	}
	// The synthetic text block must be closed before message_delta.
	if !strings.Contains(got, "content_block_stop") {
		t.Fatalf("missing content_block_stop: %s", got)
	}
	if !strings.HasSuffix(strings.TrimSpace(got), `data: {"type":"message_stop"}`) {
		t.Fatalf("stream must end with message_stop: %q", blocks[len(blocks)-1])
	}
	if result.Usage == nil || result.Usage.InputTokens != 5 || result.Usage.OutputTokens != 9 {
		t.Fatalf("usage = %#v", result.Usage)
	}
	if len(result.ToolCalls) != 1 || result.ToolCalls[0].Name != "get_weather" {
		t.Fatalf("tool calls = %#v", result.ToolCalls)
	}
	if result.FinishReason != "tool_calls" {
		t.Fatalf("finish = %q", result.FinishReason)
	}
}
