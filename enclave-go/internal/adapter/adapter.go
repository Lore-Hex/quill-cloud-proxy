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
	"math"
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
	if err := RejectUnsupportedN(req); err != nil {
		return nil, err
	}
	if len(req.Messages) == 0 {
		return nil, &AdapterError{Status: 400, Message: "messages must contain at least one entry"}
	}
	var systemParts []string
	var systemBlocks []map[string]any
	systemHasCacheControl := false
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
			for _, block := range anthropicSystemBlocks(m.Content) {
				if _, ok := block["cache_control"]; ok {
					systemHasCacheControl = true
				}
				systemBlocks = append(systemBlocks, block)
			}
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
		StopSequences:     req.StopSequences(),
		Metadata:          anthropicUserIDMetadata(req.Metadata),
	}
	if thinking := anthropicThinkingFromChat(req, out.MaxTokens); thinking != nil {
		out.Thinking = thinking
		out.AnthropicMaxTokens = anthropicMaxTokensForThinking(out.MaxTokens, thinking)
	}
	if len(systemParts) > 0 {
		out.System = strings.Join(systemParts, "\n\n")
	}
	// When the client pinned a prompt-cache breakpoint on a system block, send
	// the system field as Anthropic content blocks (SystemRaw) so the marker
	// survives — the system prompt is the dominant prompt-cache target. Only when
	// a breakpoint is actually present, so the common case keeps the flattened
	// string form. out.System stays populated for token estimation and any
	// upstream that reads only the string.
	if systemHasCacheControl {
		raw := make([]any, len(systemBlocks))
		for i, block := range systemBlocks {
			raw[i] = block
		}
		out.SystemRaw = raw
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

func anthropicUserIDMetadata(m map[string]any) map[string]any {
	v, ok := m["user_id"].(string)
	if !ok || v == "" {
		return nil
	}
	return map[string]any{"user_id": v}
}

func anthropicThinkingFromChat(req *types.OpenAIChatRequest, maxTokens int) any {
	budget, ok := anthropicThinkingBudget(req)
	if !ok {
		return nil
	}
	if budget <= 0 {
		return nil
	}
	if maxTokens > 1 && budget >= maxTokens {
		return map[string]any{"type": "enabled", "budget_tokens": budget}
	}
	if maxTokens > 1 && budget == maxTokens {
		budget = maxTokens - 1
	}
	return map[string]any{"type": "enabled", "budget_tokens": budget}
}

func anthropicMaxTokensForThinking(maxTokens int, thinking any) int {
	budget := anthropicThinkingBudgetFromConfig(thinking)
	if budget <= 0 || maxTokens > budget {
		return maxTokens
	}
	if maxTokens > 0 {
		return budget + maxTokens
	}
	return budget + DefaultMaxTokens
}

func anthropicThinkingBudgetFromConfig(thinking any) int {
	m, ok := thinking.(map[string]any)
	if !ok {
		return 0
	}
	return intFromAny(m["budget_tokens"])
}

func anthropicThinkingBudget(req *types.OpenAIChatRequest) (int, bool) {
	if req == nil {
		return 0, false
	}
	if budget, ok := anthropicThinkingBudgetFromReasoning(req.Reasoning); ok {
		return budget, true
	}
	if budget, ok := anthropicReasoningEffortBudget(req.ReasoningEffort); ok {
		return budget, true
	}
	return 0, false
}

func anthropicThinkingBudgetFromReasoning(reasoning any) (int, bool) {
	switch value := reasoning.(type) {
	case nil:
		return 0, false
	case bool:
		if value {
			return anthropicEffortBudget("medium"), true
		}
		return 0, false
	case string:
		return anthropicReasoningEffortBudget(value)
	case map[string]any:
		for _, key := range []string{"max_tokens", "thinking_budget", "budget_tokens"} {
			if n := intFromAny(value[key]); n > 0 {
				return n, true
			}
		}
		if effort, _ := value["effort"].(string); effort != "" {
			return anthropicReasoningEffortBudget(effort)
		}
		if typ, _ := value["type"].(string); strings.EqualFold(typ, "enabled") || strings.EqualFold(typ, "adaptive") {
			return anthropicEffortBudget("medium"), true
		}
		if enabled, _ := value["enabled"].(bool); enabled {
			return anthropicEffortBudget("medium"), true
		}
	}
	return 0, false
}

func anthropicReasoningEffortBudget(effort string) (int, bool) {
	normalized := strings.TrimSpace(strings.ToLower(effort))
	switch normalized {
	case "low":
		return anthropicEffortBudget(normalized), true
	case "medium":
		return anthropicEffortBudget(normalized), true
	case "high", "xhigh":
		return anthropicEffortBudget(normalized), true
	case "", "none", "off", "disable", "disabled", "minimal":
		return 0, false
	default:
		return 0, false
	}
}

func anthropicEffortBudget(effort string) int {
	switch effort {
	case "low":
		return 1024
	case "high", "xhigh":
		return 8192
	default:
		return 4096
	}
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return 0
		}
		return int(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	}
	return 0
}

func RejectUnsupportedN(req *types.OpenAIChatRequest) error {
	if req == nil || req.N == nil || *req.N <= 1 {
		return nil
	}
	return &AdapterError{Status: 400, Message: "n>1 is not supported", Context: "n"}
}

func RejectUnsupportedNForProvider(req *types.OpenAIChatRequest, provider, model string) error {
	_ = provider
	_ = model
	return RejectUnsupportedN(req)
}

// anthropicSystemBlocks converts a chat `system` message's content into
// Anthropic system content blocks, preserving any client-sent cache_control on
// each text part. A plain string becomes a single text block. Non-text parts
// (images are already rejected upstream) and empty text are skipped. Callers
// only promote these to SystemRaw when at least one carries a breakpoint.
func anthropicSystemBlocks(content any) []map[string]any {
	appendPart := func(blocks []map[string]any, text string, cacheControl any) []map[string]any {
		if strings.TrimSpace(text) == "" {
			return blocks
		}
		block := map[string]any{"type": "text", "text": text}
		if cacheControl != nil {
			block["cache_control"] = cacheControl
		}
		return append(blocks, block)
	}
	switch value := content.(type) {
	case string:
		return appendPart(nil, value, nil)
	case []types.ChatContentPart:
		var blocks []map[string]any
		for _, part := range value {
			if isSystemTextPart(part.Type) {
				blocks = appendPart(blocks, part.Text, part.CacheControl)
			}
		}
		return blocks
	case []any:
		var blocks []map[string]any
		for _, item := range value {
			m, ok := item.(map[string]any)
			if !ok || !isSystemTextPart(stringValue(m["type"])) {
				continue
			}
			blocks = appendPart(blocks, stringValue(m["text"]), m["cache_control"])
		}
		return blocks
	default:
		return nil
	}
}

func isSystemTextPart(partType string) bool {
	switch partType {
	case "", "text", "input_text":
		return true
	default:
		return false
	}
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

func JoinThinking(thinking []ThinkingBlock) string {
	if len(thinking) == 0 {
		return ""
	}
	var joined strings.Builder
	for _, block := range thinking {
		joined.WriteString(block.Text)
	}
	return joined.String()
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
	// InputExcludesCache is true when InputTokens counts ONLY the uncached
	// prompt remainder (the Anthropic convention: input_tokens excludes cache
	// reads/writes, which are reported separately). It is false for
	// OpenAI-compatible and Gemini upstreams, whose prompt counts already
	// INCLUDE the cached subset. Set only when native-Anthropic usage arrives
	// on a message_start event (the OpenAI/Gemini translators never emit one).
	// chatCompletionUsage uses it to fold cache tokens back into prompt_tokens
	// for Anthropic without double-counting providers that already include them.
	InputExcludesCache bool
}

func WriteChatCompletionResponse(
	w io.Writer,
	requestID string,
	model string,
	text string,
	reasoning string,
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
	// Cached/reasoning detail counts come from the upstream-reported usage.
	// NOTE: usage may be non-nil even when inputTokens is a chars/4 estimate
	// (realOrEstimatedTokens substitutes an estimated input while returning the
	// real usage), so the prompt_tokens fold in chatCompletionUsage clamps
	// cached_tokens to remain a subset. inputTokens/outputTokens stay as the
	// real-or-estimated totals the caller computed.
	cachedTokens, cacheCreationTokens, reasoningTokens := 0, 0, 0
	inputExcludesCache := false
	if usage != nil {
		cachedTokens = usage.CacheReadInputTokens
		cacheCreationTokens = usage.CacheCreationInputTokens
		reasoningTokens = usage.ReasoningTokens
		inputExcludesCache = usage.InputExcludesCache
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
	if reasoning != "" {
		message["reasoning"] = reasoning
		message["reasoning_content"] = reasoning
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
		"usage": chatCompletionUsage(inputTokens, outputTokens, cachedTokens, cacheCreationTokens, reasoningTokens, inputExcludesCache),
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
	return TransformStreamCaptureWithRouterMetadata(r, w, requestID, model, emitUsageChunk, nil)
}

func TransformStreamCaptureWithRouterMetadata(
	r io.Reader,
	w io.Writer,
	requestID string,
	model string,
	emitUsageChunk bool,
	routerMetadata map[string]any,
) (StreamResult, error) {
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
		if len(routerMetadata) > 0 {
			if err := writeRouterMetadataChunk(w, requestID, model, created, routerMetadata); err != nil {
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
			mergeMessageStartUsage(&usage, getMap(dataJSON, "message"))
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
					"reasoning":         deltaText,
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

func writeRouterMetadataChunk(
	w io.Writer,
	id string,
	model string,
	created int64,
	metadata map[string]any,
) error {
	payload := map[string]any{
		"id":                  id,
		"object":              "chat.completion.chunk",
		"created":             created,
		"model":               model,
		"choices":             []any{},
		"openrouter_metadata": metadata,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "data: %s\n\n", body)
	return err
}

// streamToolCall accumulates one tool_use block while its OpenAI-shaped
// deltas stream out incrementally.
type streamToolCall struct {
	openAIIndex int
	id          string
	name        string
	args        strings.Builder
}

// mergeMessageStartUsage folds a native-Anthropic message_start usage object
// into the running total and records the Anthropic accounting convention
// (input_tokens EXCLUSIVE of cache). Only native Anthropic emits message_start;
// the OpenAI-compatible and Gemini translators relay usage on a synthetic
// message_delta with a cache-INCLUSIVE input_tokens (see llm/stream_translate.go
// writeAnthropicStop), so this is the reliable point to distinguish the two.
//
// The convention is marked whenever the event carried a usage OBJECT — even an
// all-zero one — so a stream that reports input_tokens:0 up front and only
// carries cache_read_input_tokens on a later message_delta is still recognized
// as Anthropic. Otherwise mergeUsage would not allocate for the all-zero
// message_start, InputExcludesCache would stay false, and the fully-cached
// prompt would surface as cached_tokens > prompt_tokens (prompt_tokens:0).
func mergeMessageStartUsage(usage **StreamUsage, message map[string]any) {
	if message == nil {
		return
	}
	m := getMap(message, "usage")
	if m == nil {
		return
	}
	mergeUsage(usage, m)
	if *usage == nil {
		*usage = &StreamUsage{}
	}
	(*usage).InputExcludesCache = true
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

// foldedPromptTokens returns the OpenAI-style FULL prompt token count, shared by
// the chat-completions and Responses usage builders. Anthropic reports its input
// count EXCLUSIVE of cache (inputExcludesCache), so cache read/creation tokens
// are added back to keep the prompt total a superset of cached_tokens;
// OpenAI-compatible and Gemini upstreams already include the cached subset, so
// their count passes through unchanged.
func foldedPromptTokens(inputTokens, cachedTokens, cacheCreationTokens int, inputExcludesCache bool) int {
	prompt := inputTokens
	if inputExcludesCache {
		prompt += cachedTokens + cacheCreationTokens
	}
	// Guarantee cached_tokens stays a subset of prompt_tokens even when
	// inputTokens is a chars/4 estimate that undershoots the reported cache
	// (e.g. a degenerate upstream usage with prompt_tokens:0 but cache_read>0):
	// the cached and cache-written tokens are by definition part of the prompt.
	if floor := cachedTokens + cacheCreationTokens; prompt < floor {
		prompt = floor
	}
	return prompt
}

// chatCompletionUsage builds the OpenAI `usage` object shared by the streaming
// (writeUsageChunk) and non-streaming (WriteChatCompletionResponse) paths. It
// adds the prompt_tokens_details.cached_tokens and
// completion_tokens_details.reasoning_tokens sub-objects only when those counts
// are present, matching OpenAI's documented shape. Keeping a single builder
// ensures both response shapes surface prompt-cache savings identically.
//
// OpenAI semantics require prompt_tokens to be the FULL prompt with
// cached_tokens as a subset. When inputExcludesCache is true the provider
// reported inputTokens EXCLUSIVE of cache (Anthropic), so cache-read and
// cache-write tokens are folded back into prompt_tokens/total_tokens —
// otherwise a cache hit would surface cached_tokens > prompt_tokens and any
// client computing uncached = prompt_tokens - cached_tokens goes negative.
// When false (OpenAI-compatible / Gemini) inputTokens already INCLUDES the
// cached subset, so folding would double-count and is skipped.
func chatCompletionUsage(inputTokens, outputTokens, cachedTokens, cacheCreationTokens, reasoningTokens int, inputExcludesCache bool) map[string]any {
	promptTokens := foldedPromptTokens(inputTokens, cachedTokens, cacheCreationTokens, inputExcludesCache)
	body := map[string]any{
		"prompt_tokens":     promptTokens,
		"completion_tokens": outputTokens,
		"total_tokens":      promptTokens + outputTokens,
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
	usageBody := chatCompletionUsage(usage.InputTokens, usage.OutputTokens, usage.CacheReadInputTokens, usage.CacheCreationInputTokens, usage.ReasoningTokens, usage.InputExcludesCache)
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
	case "max_tokens", "length":
		return "length"
	case types.SyntheticStopReasonContentFilter, "content_filter":
		return "content_filter"
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
