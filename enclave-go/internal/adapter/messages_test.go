package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
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
		Metadata:      map[string]any{"user_id": "user-123"},
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
	if out.Metadata["user_id"] != "user-123" {
		t.Fatalf("metadata = %#v, want user_id", out.Metadata)
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
		{Model: "m", Messages: []types.AnthropicMessage{{Role: "tool", Content: "x"}}, MaxTokens: 16},
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

func TestMessagesToAnthropicDropsRouterOnlyMetadataFromProviderBody(t *testing.T) {
	req := &AnthropicNativeRequest{
		Model:     "anthropic/claude-haiku-4.5",
		MaxTokens: 64,
		Messages:  []types.AnthropicMessage{{Role: "user", Content: "hello"}},
		User:      "router-user-marker",
		SessionID: "router-session-marker",
		Trace:     map[string]any{"router-trace-marker": true},
		Tags:      types.NewRequestTags(types.TagMap{"router-tag-marker": "legal"}),
	}
	out, err := MessagesToAnthropic(req)
	if err != nil {
		t.Fatalf("MessagesToAnthropic: %v", err)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, marker := range []string{
		"router-user-marker",
		"router-session-marker",
		"router-trace-marker",
		"router-tag-marker",
	} {
		if strings.Contains(string(encoded), marker) {
			t.Fatalf("provider payload leaked %q: %s", marker, encoded)
		}
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

func TestRelayAnthropicStreamKeepsPriceTierInputPrivate(t *testing.T) {
	for _, native := range []bool{false, true} {
		var in strings.Builder
		if native {
			in.WriteString("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_test\",\"usage\":{\"input_tokens\":6}}}\n\n")
		}
		in.WriteString("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"stop\"},\"usage\":{\"input_tokens\":1266,\"output_tokens\":22,\"price_tier_input_tokens\":6}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		var out bytes.Buffer
		result, err := RelayAnthropicStream(strings.NewReader(in.String()), &out, "msg_test", "fugu-ultra-v1.1")
		if err != nil {
			t.Fatal(err)
		}
		if result.Usage == nil || result.Usage.PriceTierInputTokens != 6 {
			t.Fatalf("native=%v captured usage=%#v", native, result.Usage)
		}
		if strings.Contains(out.String(), "price_tier_input_tokens") {
			t.Fatalf("native=%v leaked internal pricing field", native)
		}
	}
}

func TestRelayAnthropicStreamEmitsValidAnthropicStopReasonsForGeminiStops(t *testing.T) {
	valid := map[string]bool{
		"end_turn":      true,
		"max_tokens":    true,
		"stop_sequence": true,
		"tool_use":      true,
		"pause_turn":    true,
		"refusal":       true,
	}
	cases := map[string]struct {
		internalStop string
		wantStop     string
		wantFinish   string
	}{
		"Gemini MAX_TOKENS": {
			internalStop: "max_tokens",
			wantStop:     "max_tokens",
			wantFinish:   "length",
		},
		"Gemini SAFETY": {
			internalStop: types.SyntheticStopReasonContentFilter,
			wantStop:     "refusal",
			wantFinish:   "content_filter",
		},
		"legacy OpenAI length": {
			internalStop: "length",
			wantStop:     "max_tokens",
			wantFinish:   "length",
		},
		"legacy OpenAI content_filter": {
			internalStop: "content_filter",
			wantStop:     "refusal",
			wantFinish:   "content_filter",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			synthetic := strings.Join([]string{
				`event: message_delta`,
				`data: {"type":"message_delta","delta":{"stop_reason":"` + tc.internalStop + `"},"usage":{"output_tokens":1}}`,
				``,
				`event: message_stop`,
				`data: {"type":"message_stop"}`,
				``,
			}, "\n")

			var out bytes.Buffer
			result, err := RelayAnthropicStream(strings.NewReader(synthetic), &out, "msg_local", "gemini-3.1-pro")
			if err != nil {
				t.Fatalf("RelayAnthropicStream: %v", err)
			}
			if result.FinishReason != tc.wantFinish {
				t.Fatalf("finish reason = %q, want %q", result.FinishReason, tc.wantFinish)
			}
			stopReason := emittedMessageDeltaStopReason(t, out.String())
			if stopReason != tc.wantStop {
				t.Fatalf("emitted stop_reason = %q, want %q; stream=%s", stopReason, tc.wantStop, out.String())
			}
			if !valid[stopReason] {
				t.Fatalf("emitted invalid Anthropic stop_reason %q", stopReason)
			}
			if stopReason == "length" || stopReason == "content_filter" {
				t.Fatalf("emitted OpenAI vocabulary stop_reason %q", stopReason)
			}
		})
	}
}

func emittedMessageDeltaStopReason(t *testing.T, stream string) string {
	t.Helper()
	for _, block := range strings.Split(strings.TrimSpace(stream), "\n\n") {
		if !strings.Contains(block, "event: message_delta") {
			continue
		}
		dataStart := strings.Index(block, "data: ")
		if dataStart < 0 {
			t.Fatalf("message_delta missing data: %q", block)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(block[dataStart+len("data: "):]), &payload); err != nil {
			t.Fatalf("decode message_delta: %v", err)
		}
		delta, ok := payload["delta"].(map[string]any)
		if !ok {
			t.Fatalf("message_delta missing delta: %#v", payload)
		}
		reason, ok := delta["stop_reason"].(string)
		if !ok {
			t.Fatalf("message_delta missing stop_reason: %#v", delta)
		}
		return reason
	}
	t.Fatalf("message_delta not emitted: %s", stream)
	return ""
}

func TestMessagesTerminalHookPreservesEventsAndOptionalUsage(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, includeUsage := range []bool{false, true} {
			t.Run(fmt.Sprintf("native=%t/usage=%t", native, includeUsage), func(t *testing.T) {
				wire := ""
				if native {
					wire = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_provider\",\"usage\":{\"input_tokens\":2,\"output_tokens\":0}}}\n\n"
				}
				wire += "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n"
				usageJSON := ""
				if includeUsage {
					usageJSON = `,"usage":{"output_tokens":3}`
				}
				wire += "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null}" + usageJSON + "}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
				var original, annotated bytes.Buffer
				if _, err := RelayAnthropicStream(strings.NewReader(wire), &original, "msg_gateway", "model"); err != nil {
					t.Fatal(err)
				}
				calls := 0
				result, err := RelayAnthropicStreamWithTerminalHook(strings.NewReader(wire), &annotated, "msg_gateway", "model", func(terminal StreamTerminal) error {
					calls++
					if terminal.Result.Text != "Hello" || terminal.FinishReason != "stop" || terminal.UsageFields == nil {
						t.Fatalf("terminal = %+v", terminal)
					}
					if includeUsage {
						if terminal.Result.Usage.OutputTokens != 3 {
							t.Fatalf("usage = %+v", terminal.Result.Usage)
						}
					}
					terminal.UsageFields["cost_microdollars"] = 83
					terminal.UsageFields["total_cost_microdollars"] = 83
					return terminal.Emit()
				})
				if err != nil || calls != 1 || result.Text != "Hello" {
					t.Fatalf("result=%+v err=%v calls=%d", result, err, calls)
				}
				oldBlocks, newBlocks := strings.Split(original.String(), "\n\n"), strings.Split(annotated.String(), "\n\n")
				if len(oldBlocks) != len(newBlocks) {
					t.Fatal("event count changed")
				}
				for index, block := range oldBlocks {
					oldName, oldBody := parseSSEBlock([]byte(block))
					newName, newBody := parseSSEBlock([]byte(newBlocks[index]))
					if newName == "message_delta" {
						usage := getMap(newBody, "usage")
						if usage["cost_microdollars"] != float64(83) || usage["total_cost_microdollars"] != float64(83) {
							t.Fatalf("usage = %+v", usage)
						}
						delete(usage, "cost_microdollars")
						delete(usage, "total_cost_microdollars")
						if !includeUsage {
							delete(newBody, "usage")
						}
					}
					if oldName != newName || !reflect.DeepEqual(oldBody, newBody) {
						t.Fatalf("event %d changed: %s => %s", index, block, newBlocks[index])
					}
				}
			})
		}
	}
}

// This is the literal Claude Code 2.1.330 second tool-loop request, including
// unsupported fields that decoding has always ignored.
func TestMessagesCapturedClaudeCodeSystemRole(t *testing.T) {
	body, err := os.ReadFile("testdata/claude-code-messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var req AnthropicNativeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	out, err := MessagesToAnthropic(&req)
	if err != nil {
		t.Fatal(err)
	}
	want := decodeNativeMessages(t, `[
		{"role":"user","content":[{"type":"text","text":"U1"},{"type":"text","text":"U2"},{"type":"text","text":"REMINDER TEXT"}]},
		{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/tmp/notes.txt"}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"heliotrope"}]}
	]`)
	if !reflect.DeepEqual(out.Messages, want) {
		t.Fatalf("messages = %#v, want %#v", out.Messages, want)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Messages     []map[string]any `json:"messages"`
		OutputConfig any              `json:"output_config"`
	}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"role":"system"`) {
		t.Fatalf("system role forwarded: %s", encoded)
	}
	for _, message := range wire.Messages {
		if len(message) != 2 || message["role"] == nil || message["content"] == nil {
			t.Fatalf("message keys must be only role and content: %#v", message)
		}
		if _, ok := message["output_config"]; ok {
			t.Fatalf("per-turn output_config forwarded: %#v", message)
		}
	}
	if !reflect.DeepEqual(wire.OutputConfig, map[string]any{"effort": "medium"}) {
		t.Fatalf("top-level output_config = %#v", wire.OutputConfig)
	}
	shim := MessagesToChatShim(&req)
	wantShim := []types.OpenAIChatMessage{{Role: "system", Content: "S1\n\nS2\n\nS3"}}
	for _, m := range want {
		wantShim = append(wantShim, types.OpenAIChatMessage{Role: m.Role, Content: m.Content})
	}
	if shim == nil || !reflect.DeepEqual(shim.Messages, wantShim) {
		t.Fatalf("shim = %#v, want messages %#v", shim, wantShim)
	}
}

func decodeNativeMessages(t *testing.T, body string) []types.AnthropicMessage {
	t.Helper()
	var messages []types.AnthropicMessage
	if err := json.Unmarshal([]byte(body), &messages); err != nil {
		t.Fatal(err)
	}
	return messages
}

func TestMessagesSystemRolePlacement(t *testing.T) {
	text := func(s string) any { return map[string]any{"type": "text", "text": s} }
	user := types.AnthropicMessage{Role: "user", Content: []any{text("U")}}
	assistant := types.AnthropicMessage{Role: "assistant", Content: []any{map[string]any{"type": "tool_use", "id": "toolu_1", "name": "Read", "input": map[string]any{"file_path": "/tmp/notes.txt"}}}}
	result := types.AnthropicMessage{Role: "user", Content: []any{map[string]any{"type": "tool_result", "tool_use_id": "toolu_1", "content": "heliotrope"}}}
	for _, n := range []int{1, 2, 3} {
		var systems []types.AnthropicMessage
		var blocks []any
		for i := 1; i <= n; i++ {
			s := fmt.Sprintf("S%d", i)
			systems = append(systems, types.AnthropicMessage{Role: "system", Content: s})
			blocks = append(blocks, text(s))
		}
		own := types.AnthropicMessage{Role: "user", Content: blocks}
		withUser := types.AnthropicMessage{Role: "user", Content: append([]any{text("U")}, blocks...)}
		withResult := types.AnthropicMessage{Role: "user", Content: append([]any{result.Content.([]any)[0]}, blocks...)}
		// A run of systems is placed as one: before a user message it joins
		// that message after its blocks, so a tool_result still directly
		// answers the tool_use before the run.
		userThenSystems := types.AnthropicMessage{Role: "user", Content: append([]any{text("U")}, blocks...)}
		firstUser := []types.AnthropicMessage{userThenSystems}
		betweenTool := []types.AnthropicMessage{assistant, withResult}
		for _, tc := range []struct {
			name                string
			before, after, want []types.AnthropicMessage
		}{
			{"first before assistant", nil, []types.AnthropicMessage{assistant}, []types.AnthropicMessage{own, assistant}},
			{"first before user", nil, []types.AnthropicMessage{user}, firstUser},
			{"last after assistant", []types.AnthropicMessage{assistant}, nil, []types.AnthropicMessage{assistant, own}},
			{"last after user", []types.AnthropicMessage{user}, nil, []types.AnthropicMessage{withUser}},
			{"between tool use and result", []types.AnthropicMessage{assistant}, []types.AnthropicMessage{result}, betweenTool},
			{"between user and assistant", []types.AnthropicMessage{user}, []types.AnthropicMessage{assistant}, []types.AnthropicMessage{withUser, assistant}},
			{"between assistants", []types.AnthropicMessage{assistant}, []types.AnthropicMessage{assistant}, []types.AnthropicMessage{assistant, own, assistant}},
			{"between users", []types.AnthropicMessage{user}, []types.AnthropicMessage{user}, []types.AnthropicMessage{withUser, user}},
		} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, n), func(t *testing.T) {
				input := append(append(append([]types.AnthropicMessage{}, tc.before...), systems...), tc.after...)
				out, err := MessagesToAnthropic(&AnthropicNativeRequest{Model: "m", MaxTokens: 16, Messages: input})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(out.Messages, tc.want) {
					t.Fatalf("messages = %#v, want %#v", out.Messages, tc.want)
				}
				shim := MessagesToChatShim(&AnthropicNativeRequest{Messages: input})
				var shimMessages []types.AnthropicMessage
				for _, m := range shim.Messages {
					shimMessages = append(shimMessages, types.AnthropicMessage{Role: m.Role, Content: m.Content})
				}
				if !reflect.DeepEqual(shimMessages, tc.want) {
					t.Fatalf("shim messages = %#v, want %#v", shimMessages, tc.want)
				}
			})
		}
	}
}

func TestMessagesSystemRoleContent(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"string user upgraded", `[{"role":"user","content":"U"},{"role":"system","content":"S"}]`, `[{"role":"user","content":[{"type":"text","text":"U"},{"type":"text","text":"S"}]}]`},
		{"next string user upgraded", `[{"role":"system","content":"S"},{"role":"user","content":"U"}]`, `[{"role":"user","content":[{"type":"text","text":"U"},{"type":"text","text":"S"}]}]`},
		{"cache control and sanitation", `[{"role":"system","content":[{"type":"text","text":""},{"type":"text","text":"S1","cache_control":{"type":"ephemeral"}},{"type":"text","text":"S2"},{"type":"text","text":"  "}]}]`, `[{"role":"user","content":[{"type":"text","text":"S1","cache_control":{"type":"ephemeral"}},{"type":"text","text":"S2"}]}]`},
		{"empty string", `[{"role":"user","content":"U"},{"role":"system","content":"","output_config":{"effort":"medium"}}]`, `[{"role":"user","content":"U"}]`},
		{"whitespace", `[{"role":"system","content":" \n\t"},{"role":"user","content":"U"}]`, `[{"role":"user","content":"U"}]`},
		{"empty list", `[{"role":"user","content":"U"},{"role":"system","content":[]}]`, `[{"role":"user","content":"U"}]`},
		{"empty blocks", `[{"role":"user","content":"U"},{"role":"system","content":[{"type":"text","text":""},{"type":"text","text":" \n","cache_control":{"type":"ephemeral"}}]}]`, `[{"role":"user","content":"U"}]`},
		{"empty among systems", `[{"role":"system","content":"S1"},{"role":"system","content":" "},{"role":"system","content":"S2"},{"role":"user","content":"U"}]`, `[{"role":"user","content":[{"type":"text","text":"U"},{"type":"text","text":"S1"},{"type":"text","text":"S2"}]}]`},
		{"no systems", `[{"role":"user","content":"U"},{"role":"assistant","content":[{"type":"text","text":"A"}]}]`, `[{"role":"user","content":"U"},{"role":"assistant","content":[{"type":"text","text":"A"}]}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := MessagesToAnthropic(&AnthropicNativeRequest{Model: "m", MaxTokens: 16, Messages: decodeNativeMessages(t, tc.input)})
			if err != nil {
				t.Fatal(err)
			}
			want := decodeNativeMessages(t, tc.want)
			if !reflect.DeepEqual(out.Messages, want) {
				t.Fatalf("messages = %#v, want %#v", out.Messages, want)
			}
		})
	}
}

func TestMessagesSystemRoleErrors(t *testing.T) {
	for _, content := range []string{`[{"type":"image"}]`, `42`, `null`, `{}`, `true`, `["text"]`, `[{"type":"text"}]`, `[{"type":"text","text":42}]`, `[{"type":"text","text":""},{"type":"tool_result"}]`, `[{"type":"document","text":"D"}]`, `[{"text":"untyped"}]`} {
		t.Run(content, func(t *testing.T) {
			input := decodeNativeMessages(t, `[{"role":"system","content":""},{"role":"system","content":`+content+`}]`)
			_, err := MessagesToAnthropic(&AnthropicNativeRequest{Model: "m", MaxTokens: 16, Messages: input})
			want := &AdapterError{Status: 400, Message: "unsupported system message content", Context: "messages[1].content"}
			if !reflect.DeepEqual(err, want) {
				t.Fatalf("error = %#v, want %#v", err, want)
			}
			if shim := MessagesToChatShim(&AnthropicNativeRequest{Messages: input}); shim != nil {
				t.Fatalf("invalid system content accepted by shim: %#v", shim)
			}
		})
	}
	for _, role := range []string{"tool", "developer", ""} {
		t.Run("role="+role, func(t *testing.T) {
			input := []types.AnthropicMessage{{Role: "system", Content: ""}, {Role: role, Content: "x"}}
			_, err := MessagesToAnthropic(&AnthropicNativeRequest{Model: "m", MaxTokens: 16, Messages: input})
			want := &AdapterError{Status: 400, Message: "unsupported role", Context: fmt.Sprintf("messages[1].role=%q", role)}
			if !reflect.DeepEqual(err, want) {
				t.Fatalf("error = %#v, want %#v", err, want)
			}
		})
	}
}

func TestMessagesSystemRoleDoesNotMutateInput(t *testing.T) {
	for _, next := range []bool{false, true} {
		t.Run(fmt.Sprintf("next=%t", next), func(t *testing.T) {
			// Spare capacity and an observable tail catch append into the input's
			// backing array even when the visible input length stays unchanged.
			backing := []any{map[string]any{"type": "text", "text": "U"}, map[string]any{"type": "text", "text": "tail"}}
			user := types.AnthropicMessage{Role: "user", Content: backing[:1]}
			system := types.AnthropicMessage{Role: "system", Content: []any{map[string]any{"type": "text", "text": "S", "cache_control": map[string]any{"type": "ephemeral"}}}}
			input := []types.AnthropicMessage{user, system}
			if next {
				input = []types.AnthropicMessage{system, user}
			}
			encoded, _ := json.Marshal(input)
			before := decodeNativeMessages(t, string(encoded))
			out, err := MessagesToAnthropic(&AnthropicNativeRequest{Model: "m", MaxTokens: 16, Messages: input})
			if err != nil {
				t.Fatal(err)
			}
			want := decodeNativeMessages(t, `[{"role":"user","content":[{"type":"text","text":"U"},{"type":"text","text":"S","cache_control":{"type":"ephemeral"}}]}]`)
			if !reflect.DeepEqual(out.Messages, want) {
				t.Fatalf("messages = %#v, want %#v", out.Messages, want)
			}
			_ = MessagesToChatShim(&AnthropicNativeRequest{Messages: input})
			if !reflect.DeepEqual(input, before) || backing[1].(map[string]any)["text"] != "tail" {
				t.Fatalf("input mutated: %#v; backing: %#v", input, backing)
			}
		})
	}
}
