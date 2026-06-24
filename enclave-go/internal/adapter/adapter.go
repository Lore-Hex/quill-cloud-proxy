// Package adapter translates OpenAI Chat Completions ↔ Anthropic Messages.
//
// Bedrock's InvokeModelWithResponseStream returns AWS event-stream chunks
// whose payload is identical to native Anthropic SSE event JSON; we unwrap
// once in the bedrock package and feed those events here verbatim.
package adapter

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// DefaultMaxTokens applied when the client doesn't specify one. Bedrock requires
// max_tokens, so we always provide a value.
const DefaultMaxTokens = 4096

const maxSSEBlockBytes = 64 << 20

// AdapterError signals a 4xx-class translation failure.
type AdapterError struct {
	Status  int
	Message string
	Context string
}

func (e *AdapterError) Error() string {
	if e.Context != "" {
		return fmt.Sprintf("adapter: %s [%s] (status %d)", e.Message, e.Context, e.Status)
	}
	return fmt.Sprintf("adapter: %s (status %d)", e.Message, e.Status)
}

// ToAnthropic translates an OpenAI request into an Anthropic Messages body.
func ToAnthropic(req *types.OpenAIChatRequest, defaultModel string) (*types.AnthropicMessagesRequest, error) {
	if len(req.Messages) == 0 {
		return nil, &AdapterError{Status: 400, Message: "messages must contain at least one entry"}
	}
	var systemParts []string
	var msgs []types.AnthropicMessage
	for i, m := range req.Messages {
		if types.ContentEmpty(m.Content) && len(m.ToolCalls) == 0 && m.Role != "tool" {
			continue
		}
		switch m.Role {
		case "system":
			if types.ContentImageCount(m.Content) > 0 {
				return nil, &AdapterError{
					Status:  400,
					Message: "system messages cannot contain images",
					Context: fmt.Sprintf("message[%d].content", i),
				}
			}
			systemParts = append(systemParts, types.ContentText(m.Content))
		case "user":
			msgs = append(msgs, types.AnthropicMessage{Role: m.Role, Content: m.Content})
		case "assistant":
			msgs = append(msgs, types.AnthropicMessage{Role: "assistant", Content: anthropicAssistantContent(m)})
		case "tool":
			msgs = append(msgs, types.AnthropicMessage{Role: "user", Content: anthropicToolResultContent(m)})
		default:
			return nil, &AdapterError{
				Status:  400,
				Message: "unsupported role",
				Context: fmt.Sprintf("message[%d].role=%q", i, m.Role),
			}
		}
	}
	if len(msgs) == 0 {
		return nil, &AdapterError{Status: 400, Message: "messages must contain a user/assistant turn"}
	}
	maxTokens := DefaultMaxTokens
	if req.MaxTokens != nil {
		maxTokens = *req.MaxTokens
	}
	out := &types.AnthropicMessagesRequest{
		AnthropicVersion: "bedrock-2023-05-31",
		Messages:         msgs,
		MaxTokens:        maxTokens,
		// Anthropic/Bedrock require max_tokens, so MaxTokens always has a
		// value; MaxTokensExplicit lets the OpenAI-compatible path omit the
		// parameter when the client never asked for a cap (see the field's
		// comment in types.go).
		MaxTokensExplicit: req.MaxTokens != nil,
		Temperature:       req.Temperature,
		TopP:              req.TopP,
	}
	if len(systemParts) > 0 {
		out.System = strings.Join(systemParts, "\n\n")
	}
	tools, err := AnthropicToolsFromChatTools(req.Tools)
	if err != nil {
		return nil, err
	}
	out.Tools = tools
	toolChoice, err := AnthropicToolChoiceFromChat(req.ToolChoice)
	if err != nil {
		return nil, err
	}
	out.ToolChoice = toolChoice
	_ = defaultModel // model is only used for response chunks, not the body
	return out, nil
}

func anthropicAssistantContent(m types.OpenAIChatMessage) any {
	if len(m.ToolCalls) == 0 {
		return m.Content
	}
	blocks := make([]map[string]any, 0, 1+len(m.ToolCalls))
	if text := strings.TrimSpace(types.ContentText(m.Content)); text != "" {
		blocks = append(blocks, map[string]any{"type": "text", "text": text})
	}
	for _, call := range m.ToolCalls {
		id := strings.TrimSpace(call.ID)
		if id == "" {
			id = strings.TrimSpace(call.Function.Name)
		}
		blocks = append(blocks, map[string]any{
			"type":  "tool_use",
			"id":    id,
			"name":  call.Function.Name,
			"input": toolCallInput(call.Function.Arguments),
		})
	}
	return blocks
}

func anthropicToolResultContent(m types.OpenAIChatMessage) []map[string]any {
	toolUseID := strings.TrimSpace(m.ToolCallID)
	if toolUseID == "" {
		toolUseID = strings.TrimSpace(m.Name)
	}
	content := m.Content
	if types.ContentEmpty(content) {
		content = ""
	}
	return []map[string]any{{
		"type":        "tool_result",
		"tool_use_id": toolUseID,
		"content":     content,
	}}
}

func toolCallInput(arguments string) any {
	arguments = strings.TrimSpace(arguments)
	if arguments == "" {
		return map[string]any{}
	}
	var parsed any
	if err := json.Unmarshal([]byte(arguments), &parsed); err != nil {
		return map[string]any{"arguments": arguments}
	}
	if parsed == nil {
		return map[string]any{}
	}
	return parsed
}

func AnthropicToolsFromChatTools(tools []any) ([]types.AnthropicTool, error) {
	if len(tools) == 0 {
		return nil, nil
	}
	out := make([]types.AnthropicTool, 0, len(tools))
	for _, tool := range tools {
		m, ok := tool.(map[string]any)
		if !ok {
			return nil, &AdapterError{Status: 400, Message: "tool must be an object", Context: "tools"}
		}
		if stringValue(m["type"]) != "function" {
			return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools"}
		}
		fn, ok := m["function"].(map[string]any)
		if !ok {
			return nil, &AdapterError{Status: 400, Message: "function tool is missing function object", Context: "tools.function"}
		}
		name := strings.TrimSpace(stringValue(fn["name"]))
		if name == "" {
			return nil, &AdapterError{Status: 400, Message: "function tool name is required", Context: "tools.function.name"}
		}
		schema, ok := fn["parameters"].(map[string]any)
		if !ok || len(schema) == 0 {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, types.AnthropicTool{
			Name:        name,
			Description: stringValue(fn["description"]),
			InputSchema: schema,
		})
	}
	return out, nil
}

func AnthropicToolChoiceFromChat(choice any) (*types.AnthropicToolChoice, error) {
	switch value := choice.(type) {
	case nil:
		return nil, nil
	case string:
		switch value {
		case "", "auto":
			return &types.AnthropicToolChoice{Type: "auto"}, nil
		case "none":
			return nil, nil
		case "required":
			return &types.AnthropicToolChoice{Type: "any"}, nil
		default:
			return nil, &AdapterError{Status: 400, Message: "invalid tool_choice", Context: "tool_choice"}
		}
	case map[string]any:
		if stringValue(value["type"]) != "function" {
			return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tool_choice"}
		}
		name := stringValue(value["name"])
		if name == "" {
			if fn, ok := value["function"].(map[string]any); ok {
				name = stringValue(fn["name"])
			}
		}
		if strings.TrimSpace(name) == "" {
			return nil, &AdapterError{Status: 400, Message: "function tool_choice name is required", Context: "tool_choice.name"}
		}
		return &types.AnthropicToolChoice{Type: "tool", Name: name}, nil
	default:
		return nil, &AdapterError{Status: 400, Message: "invalid tool_choice", Context: "tool_choice"}
	}
}

// TransformStream reads native-Anthropic SSE events from `r` and writes
// OpenAI ChatCompletion chunks to `w`, finishing with `data: [DONE]\n\n`.
//
// Input is the unwrapped stream of `event: ...\ndata: {...}\n\n` framings.
func TransformStream(r io.Reader, w io.Writer, requestID, model string) error {
	_, err := TransformStreamCapture(r, w, requestID, model)
	return err
}

type StreamResult struct {
	Text         string
	FinishReason string
	ToolCalls    []types.ToolCall
	// Thinking holds extended-thinking blocks (in order, before any text /
	// tool_use), reassembled from the upstream SSE. opus-4.7+ emits these
	// when output_config.effort is set; Anthropic requires them replayed
	// verbatim (with signature) on the next tool-use turn, so the
	// non-streaming Messages response must surface them — otherwise a
	// multi-turn agent loop loses its thinking and the next request 400s.
	Thinking []ThinkingBlock
	// Usage carries REAL upstream token counts when the provider reported
	// them (Anthropic message_start/message_delta usage, or the OpenAI-
	// compatible stream_options.include_usage final chunk relayed by
	// llm/stream_translate.go). nil when the upstream never reported usage
	// — callers fall back to the chars/4 estimates in that case.
	Usage *StreamUsage
}

// ThinkingBlock is one reassembled extended-thinking block: the thinking
// text plus the cryptographic signature Anthropic requires on replay.
type ThinkingBlock struct {
	Text      string
	Signature string
}

// StreamUsage is the provider-reported token accounting for one stream.
type StreamUsage struct {
	InputTokens     int
	OutputTokens    int
	ReasoningTokens int // subset of OutputTokens; 0 when not reported
	// Prompt-cache accounting. CacheReadInputTokens were served from the
	// provider's prompt cache (Anthropic cache_read_input_tokens, OpenAI
	// prompt_tokens_details.cached_tokens, Gemini cachedContentTokenCount);
	// CacheCreationInputTokens were written to it (Anthropic only).
	CacheReadInputTokens     int
	CacheCreationInputTokens int
}

func WriteChatCompletionResponse(
	w io.Writer,
	requestID string,
	model string,
	text string,
	toolCalls []types.ToolCall,
	inputTokens int,
	outputTokens int,
	usage *StreamUsage,
	created int64,
	finishReason string,
) error {
	if finishReason == "" {
		finishReason = "stop"
	}
	// Cached/reasoning detail counts come from the upstream-reported usage when
	// present (nil on the chars/4 estimate fallback). inputTokens/outputTokens
	// stay as the real-or-estimated totals the caller computed.
	cachedTokens, reasoningTokens := 0, 0
	if usage != nil {
		cachedTokens = usage.CacheReadInputTokens
		reasoningTokens = usage.ReasoningTokens
	}
	message := map[string]any{
		"role":    "assistant",
		"content": text,
	}
	if len(toolCalls) > 0 {
		if finishReason == "" || finishReason == "stop" {
			finishReason = "tool_calls"
		}
		message["content"] = nil
		message["tool_calls"] = chatToolCalls(toolCalls)
	}
	payload := map[string]any{
		"id":      requestID,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": []map[string]any{
			{
				"index":         0,
				"message":       message,
				"finish_reason": finishReason,
			},
		},
		"usage": chatCompletionUsage(inputTokens, outputTokens, cachedTokens, reasoningTokens),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func chatToolCalls(toolCalls []types.ToolCall) []map[string]any {
	out := make([]map[string]any, 0, len(toolCalls))
	for i, call := range toolCalls {
		id := call.ID
		if id == "" {
			id = call.CallID
		}
		if id == "" {
			id = fmt.Sprintf("call_%d", i+1)
		}
		out = append(out, map[string]any{
			"id":    id,
			"type":  "function",
			"index": i,
			"function": map[string]any{
				"name":      call.Name,
				"arguments": call.Arguments,
			},
		})
	}
	return out
}

func TransformStreamCapture(r io.Reader, w io.Writer, requestID, model string) (StreamResult, error) {
	return TransformStreamCaptureWithOptions(r, w, requestID, model, false)
}

// StreamDelta is one provider-native streaming delta after it has been
// normalized to the enclave's Anthropic-shaped internal stream contract.
type StreamDelta struct {
	Type      string
	Index     int
	Text      string
	Signature string
}

type StreamObserver func(StreamDelta)

// TransformStreamCaptureWithOptions is TransformStreamCapture plus the
// OpenAI stream_options.include_usage behavior: when emitUsageChunk is
// true and the upstream reported usage, a final chunk with empty
// `choices` and a populated `usage` object is written after the
// finish-reason chunk and before `data: [DONE]` — the shape OpenAI SDKs
// expect. Usage is captured into the StreamResult either way so
// settlement can bill real token counts instead of chars/4 estimates.
func TransformStreamCaptureWithOptions(r io.Reader, w io.Writer, requestID, model string, emitUsageChunk bool) (StreamResult, error) {
	created := time.Now().Unix()
	finishReason := "stop"
	roleSent := false
	var captured strings.Builder
	var usage *StreamUsage
	toolByBlock := map[int]*streamToolCall{}
	var toolBlockOrder []int
	thinkingByIndex := map[int]*ThinkingBlock{}
	var thinkingOrder []int

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSEBlockBytes)
	scanner.Split(splitDoubleNewline)

	// OpenAI streams open with a role chunk before any delta — text or
	// tool_calls alike.
	sendRole := func() error {
		if roleSent {
			return nil
		}
		roleSent = true
		return writeChunk(w, requestID, model, created, map[string]any{"role": "assistant", "content": ""}, "")
	}

	finish := func() (StreamResult, error) {
		if err := writeChunk(w, requestID, model, created, map[string]any{}, finishReason); err != nil {
			return StreamResult{}, err
		}
		if emitUsageChunk && usage != nil {
			if err := writeUsageChunk(w, requestID, model, created, usage); err != nil {
				return StreamResult{}, err
			}
		}
		_, err := w.Write([]byte("data: [DONE]\n\n"))
		result := StreamResult{Text: captured.String(), FinishReason: finishReason, Usage: usage, Thinking: orderedThinking(thinkingByIndex, thinkingOrder)}
		for _, blockIndex := range toolBlockOrder {
			call := toolByBlock[blockIndex]
			result.ToolCalls = append(result.ToolCalls, types.ToolCall{
				ID:        call.id,
				CallID:    call.id,
				Name:      call.name,
				Arguments: call.args.String(),
			})
		}
		return result, err
	}

	for scanner.Scan() {
		block := scanner.Bytes()
		eventName, dataJSON := parseSSEBlock(block)
		if dataJSON == nil {
			continue
		}
		switch eventName {
		case "message_start":
			// Native Anthropic streams report input_tokens up front:
			// {"type":"message_start","message":{...,"usage":{"input_tokens":N,...}}}
			if message := getMap(dataJSON, "message"); message != nil {
				mergeUsage(&usage, getMap(message, "usage"))
			}
		case "content_block_start":
			blockJSON := getMap(dataJSON, "content_block")
			if blockJSON == nil {
				continue
			}
			if getString(blockJSON, "type") == "thinking" {
				blockIndex := getInt(dataJSON, "index")
				if _, ok := thinkingByIndex[blockIndex]; !ok {
					thinkingOrder = append(thinkingOrder, blockIndex)
				}
				thinkingByIndex[blockIndex] = &ThinkingBlock{
					Text:      getString(blockJSON, "thinking"),
					Signature: getString(blockJSON, "signature"),
				}
				continue
			}
			if getString(blockJSON, "type") != "tool_use" {
				continue
			}
			blockIndex := getInt(dataJSON, "index")
			if _, ok := toolByBlock[blockIndex]; ok {
				continue
			}
			call := &streamToolCall{
				openAIIndex: len(toolBlockOrder),
				id:          getString(blockJSON, "id"),
				name:        getString(blockJSON, "name"),
			}
			toolByBlock[blockIndex] = call
			toolBlockOrder = append(toolBlockOrder, blockIndex)
			if err := sendRole(); err != nil {
				return StreamResult{}, err
			}
			if err := writeChunk(w, requestID, model, created, map[string]any{
				"tool_calls": []map[string]any{{
					"index": call.openAIIndex,
					"id":    call.id,
					"type":  "function",
					"function": map[string]any{
						"name":      call.name,
						"arguments": "",
					},
				}},
			}, ""); err != nil {
				return StreamResult{}, err
			}
		case "content_block_delta":
			delta := getMap(dataJSON, "delta")
			if delta == nil {
				continue
			}
			switch getString(delta, "type") {
			case "text_delta":
				deltaText := getString(delta, "text")
				if deltaText == "" {
					continue
				}
				_, _ = captured.WriteString(deltaText)
				if err := sendRole(); err != nil {
					return StreamResult{}, err
				}
				if err := writeChunk(w, requestID, model, created, map[string]any{"content": deltaText}, ""); err != nil {
					return StreamResult{}, err
				}
			case "thinking_delta":
				deltaText := getString(delta, "thinking")
				if deltaText == "" {
					continue
				}
				blockIndex := getInt(dataJSON, "index")
				if tb := thinkingByIndex[blockIndex]; tb != nil {
					tb.Text += deltaText
				}
				if err := sendRole(); err != nil {
					return StreamResult{}, err
				}
				if err := writeChunk(w, requestID, model, created, map[string]any{
					"reasoning_content": deltaText,
					"thinking":          deltaText,
				}, ""); err != nil {
					return StreamResult{}, err
				}
			case "signature_delta":
				signature := getString(delta, "signature")
				if signature == "" {
					continue
				}
				blockIndex := getInt(dataJSON, "index")
				if tb := thinkingByIndex[blockIndex]; tb != nil {
					tb.Signature += signature
				}
			case "input_json_delta":
				call := toolByBlock[getInt(dataJSON, "index")]
				if call == nil {
					continue
				}
				partial := getString(delta, "partial_json")
				if partial == "" {
					continue
				}
				call.args.WriteString(partial)
				if err := writeChunk(w, requestID, model, created, map[string]any{
					"tool_calls": []map[string]any{{
						"index":    call.openAIIndex,
						"function": map[string]any{"arguments": partial},
					}},
				}, ""); err != nil {
					return StreamResult{}, err
				}
			}
		case "message_delta":
			delta := getMap(dataJSON, "delta")
			if delta != nil {
				if reason := getString(delta, "stop_reason"); reason != "" {
					finishReason = mapStopReason(reason)
				}
			}
			// Anthropic puts cumulative output_tokens on message_delta;
			// stream_translate.go's synthetic stop event also carries
			// input_tokens/reasoning_tokens relayed from OpenAI-compatible
			// upstreams' include_usage final chunk.
			mergeUsage(&usage, getMap(dataJSON, "usage"))
		case "message_stop":
			return finish()
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return StreamResult{}, err
	}
	return finish()
}

// streamToolCall accumulates one tool_use block while its OpenAI-shaped
// deltas stream out incrementally.
type streamToolCall struct {
	openAIIndex int
	id          string
	name        string
	args        strings.Builder
}

// mergeUsage folds one Anthropic-shaped usage object into the running
// total, keeping previously seen non-zero fields (input_tokens arrives in
// message_start, output_tokens in message_delta).
func mergeUsage(usage **StreamUsage, m map[string]any) {
	if m == nil {
		return
	}
	in := getInt(m, "input_tokens")
	out := getInt(m, "output_tokens")
	reasoning := getInt(m, "reasoning_tokens")
	cacheRead := getInt(m, "cache_read_input_tokens")
	cacheCreation := getInt(m, "cache_creation_input_tokens")
	if in == 0 && out == 0 && reasoning == 0 && cacheRead == 0 && cacheCreation == 0 {
		return
	}
	if *usage == nil {
		*usage = &StreamUsage{}
	}
	if in > 0 {
		(*usage).InputTokens = in
	}
	if out > 0 {
		(*usage).OutputTokens = out
	}
	if reasoning > 0 {
		(*usage).ReasoningTokens = reasoning
	}
	if cacheRead > 0 {
		(*usage).CacheReadInputTokens = cacheRead
	}
	if cacheCreation > 0 {
		(*usage).CacheCreationInputTokens = cacheCreation
	}
}

// chatCompletionUsage builds the OpenAI `usage` object shared by the streaming
// (writeUsageChunk) and non-streaming (WriteChatCompletionResponse) paths. It
// adds the prompt_tokens_details.cached_tokens and
// completion_tokens_details.reasoning_tokens sub-objects only when those counts
// are present, matching OpenAI's documented shape. Keeping a single builder
// ensures both response shapes surface prompt-cache savings identically.
func chatCompletionUsage(inputTokens, outputTokens, cachedTokens, reasoningTokens int) map[string]any {
	body := map[string]any{
		"prompt_tokens":     inputTokens,
		"completion_tokens": outputTokens,
		"total_tokens":      inputTokens + outputTokens,
	}
	if reasoningTokens > 0 {
		body["completion_tokens_details"] = map[string]any{
			"reasoning_tokens": reasoningTokens,
		}
	}
	if cachedTokens > 0 {
		body["prompt_tokens_details"] = map[string]any{
			"cached_tokens": cachedTokens,
		}
	}
	return body
}

// writeUsageChunk writes the stream_options.include_usage final chunk:
// empty choices, populated usage — matching OpenAI's documented shape.
func writeUsageChunk(w io.Writer, id, model string, created int64, usage *StreamUsage) error {
	usageBody := chatCompletionUsage(usage.InputTokens, usage.OutputTokens, usage.CacheReadInputTokens, usage.ReasoningTokens)
	chunk := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []map[string]any{},
		"usage":   usageBody,
	}
	body, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte("data: ")); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n\n"))
	return err
}

// splitDoubleNewline is a bufio.Scanner SplitFunc that emits each "\n\n"-terminated block.
func splitDoubleNewline(data []byte, atEOF bool) (int, []byte, error) {
	for i := 0; i+1 < len(data); i++ {
		if data[i] == '\n' && data[i+1] == '\n' {
			return i + 2, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func parseSSEBlock(block []byte) (eventName string, dataJSON map[string]any) {
	for _, raw := range strings.Split(string(block), "\n") {
		line := strings.TrimRight(raw, "\r")
		switch {
		case strings.HasPrefix(line, "event: "):
			eventName = line[len("event: "):]
		case strings.HasPrefix(line, "data: "):
			var parsed map[string]any
			if err := json.Unmarshal([]byte(line[len("data: "):]), &parsed); err == nil {
				dataJSON = parsed
			}
		}
	}
	return
}

func getMap(m map[string]any, key string) map[string]any {
	v, ok := m[key]
	if !ok {
		return nil
	}
	out, _ := v.(map[string]any)
	return out
}

func getString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func getInt(m map[string]any, key string) int {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch value := v.(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		return 0
	}
}

func mapStopReason(reason string) string {
	switch reason {
	case "end_turn", "stop_sequence":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	default:
		return "stop"
	}
}

func writeChunk(
	w io.Writer,
	id, model string,
	created int64,
	delta map[string]any,
	finishReason string,
) error {
	chunk := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []map[string]any{
			{"index": 0, "delta": delta, "finish_reason": orNil(finishReason)},
		},
	}
	body, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte("data: ")); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n\n"))
	return err
}

func orNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}
