// Native Anthropic Messages API support (/v1/messages).
//
// The gateway pipeline is already Anthropic-shaped internally — inbound
// OpenAI requests are converted TO AnthropicMessagesRequest and every
// provider path emits native-Anthropic SSE into the adapter. So the
// Messages route is mostly pass-through: parse the native body, keep
// content blocks verbatim (NativeContent), and relay the internal SSE
// straight back to the client, normalizing the synthetic streams the
// OpenAI→Anthropic translate layer produces (they lack message_start /
// content_block_start framing that Anthropic SDKs require).
package adapter

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// AnthropicNativeRequest is the inbound POST /v1/messages shape. Fields
// the gateway cannot faithfully proxy are rejected in MessagesToAnthropic
// rather than silently dropped.
type AnthropicNativeRequest struct {
	Model         string                     `json:"model"`
	Messages      []types.AnthropicMessage   `json:"messages"`
	System        any                        `json:"system,omitempty"`
	MaxTokens     int                        `json:"max_tokens"`
	Temperature   *float64                   `json:"temperature,omitempty"`
	TopP          *float64                   `json:"top_p,omitempty"`
	Stream        bool                       `json:"stream,omitempty"`
	Tools         []types.AnthropicTool      `json:"tools,omitempty"`
	ToolChoice    *types.AnthropicToolChoice `json:"tool_choice,omitempty"`
	StopSequences []string                   `json:"stop_sequences,omitempty"`
	Thinking      any                        `json:"thinking,omitempty"`
	N             *int                       `json:"n,omitempty"`
	TopK          *int                       `json:"top_k,omitempty"`
	OutputConfig  any                        `json:"output_config,omitempty"`
	Metadata      map[string]any             `json:"metadata,omitempty"`
	Trace         map[string]any             `json:"trace,omitempty"`
	User          string                     `json:"user,omitempty"`
	SessionID     string                     `json:"session_id,omitempty"`
	Tags          *types.RequestTags         `json:"tags,omitempty"`
}

// MessagesToAnthropic validates the native request and builds the
// internal body. Content blocks pass through verbatim (NativeContent).
func MessagesToAnthropic(req *AnthropicNativeRequest) (*types.AnthropicMessagesRequest, error) {
	if strings.TrimSpace(req.Model) == "" {
		return nil, &AdapterError{Status: 400, Message: "model is required", Context: "model"}
	}
	if len(req.Messages) == 0 {
		return nil, &AdapterError{Status: 400, Message: "messages must contain at least one entry", Context: "messages"}
	}
	// Anthropic's API requires max_tokens on /v1/messages; mirroring that
	// keeps MaxTokensExplicit semantics exact (the client always chose).
	if req.MaxTokens <= 0 {
		return nil, &AdapterError{Status: 400, Message: "max_tokens is required", Context: "max_tokens"}
	}
	for i, m := range req.Messages {
		if m.Role != "user" && m.Role != "assistant" {
			return nil, &AdapterError{
				Status:  400,
				Message: "unsupported role",
				Context: fmt.Sprintf("messages[%d].role=%q", i, m.Role),
			}
		}
	}
	systemText, systemRaw := flattenSystem(req.System)
	out := &types.AnthropicMessagesRequest{
		AnthropicVersion:  "bedrock-2023-05-31",
		System:            systemText,
		SystemRaw:         systemRaw,
		Messages:          sanitizeAnthropicMessages(req.Messages),
		MaxTokens:         req.MaxTokens,
		MaxTokensExplicit: true,
		Temperature:       req.Temperature,
		TopP:              req.TopP,
		Tools:             req.Tools,
		ToolChoice:        req.ToolChoice,
		StopSequences:     req.StopSequences,
		Thinking:          req.Thinking,
		Metadata:          req.Metadata,
		TopK:              req.TopK,
		OutputConfig:      req.OutputConfig,
		NativeContent:     true,
	}
	return out, nil
}

// sanitizeAnthropicMessages drops empty/whitespace-only text blocks from each
// message's content before the body is forwarded to Anthropic.
//
// Anthropic rejects a text content block whose text is empty or all-whitespace
// ("text content blocks must be non-empty"), returning a 400 that the gateway
// surfaces as a generic 502. Multi-turn agentic clients hit this routinely: a
// model can emit a near-empty turn (e.g. a lone whitespace token, output_tokens
// ~1), and when that assistant turn is replayed verbatim in the next request —
// as the Anthropic SDK / Claude Code and other tool-loop clients do — every
// subsequent call 400s, killing the conversation. An empty text block carries
// no information, so stripping it is semantically a no-op; tool_use, tool_result,
// image, thinking, and non-empty text blocks are all preserved untouched. A
// message left with an empty content list ([]) is accepted by Anthropic, so we
// leave it rather than dropping the turn (which would desync tool_use/tool_result
// pairing or user/assistant alternation).
func sanitizeAnthropicMessages(messages []types.AnthropicMessage) []types.AnthropicMessage {
	if len(messages) == 0 {
		return messages
	}
	out := make([]types.AnthropicMessage, len(messages))
	for i, m := range messages {
		out[i] = m
		blocks, ok := m.Content.([]any)
		if !ok {
			continue // string content or unknown shape: leave verbatim
		}
		changed := false
		kept := make([]any, 0, len(blocks))
		for _, b := range blocks {
			if bm, ok := b.(map[string]any); ok {
				if t, _ := bm["type"].(string); t == "text" {
					if txt, _ := bm["text"].(string); strings.TrimSpace(txt) == "" {
						changed = true
						continue // drop empty/whitespace-only text block
					}
				}
			}
			kept = append(kept, b)
		}
		if changed {
			out[i].Content = kept
		}
	}
	return out
}

// flattenSystem splits the native system field into (flattened text,
// raw passthrough). Raw is non-nil only for block arrays — a plain
// string needs no special casing anywhere.
func flattenSystem(system any) (string, any) {
	switch value := system.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	case []any:
		var parts []string
		for _, item := range value {
			if block, ok := item.(map[string]any); ok {
				if text, ok := block["text"].(string); ok && text != "" {
					parts = append(parts, text)
				}
			}
		}
		return strings.Join(parts, "\n\n"), value
	default:
		return "", value
	}
}

// MessagesToChatShim builds the OpenAIChatRequest used for control-plane
// authorization, token estimation, and settlement metadata. Tools are
// converted to OpenAI shape so non-Anthropic upstream dispatch (which
// reads req.Tools) still sees them.
func MessagesToChatShim(req *AnthropicNativeRequest) *types.OpenAIChatRequest {
	maxTokens := req.MaxTokens
	var stop any
	if len(req.StopSequences) > 0 {
		stop = append([]string(nil), req.StopSequences...)
	}
	messages := make([]types.OpenAIChatMessage, 0, len(req.Messages)+1)
	if text, _ := flattenSystem(req.System); text != "" {
		messages = append(messages, types.OpenAIChatMessage{Role: "system", Content: text})
	}
	for _, m := range req.Messages {
		messages = append(messages, types.OpenAIChatMessage{Role: m.Role, Content: m.Content})
	}
	return &types.OpenAIChatRequest{
		Model:       req.Model,
		Messages:    messages,
		Stream:      req.Stream,
		MaxTokens:   &maxTokens,
		Stop:        stop,
		N:           req.N,
		Reasoning:   req.Thinking,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Tools:       ChatToolsFromAnthropicTools(req.Tools),
		ToolChoice:  chatToolChoiceFromAnthropic(req.ToolChoice),
		Metadata:    req.Metadata,
		Trace:       req.Trace,
		User:        req.User,
		SessionID:   req.SessionID,
		Tags:        types.CloneRequestTags(req.Tags),
	}
}

// ChatToolsFromAnthropicTools is the inverse of
// AnthropicToolsFromChatTools, for dispatching native-Messages requests
// to OpenAI-compatible upstreams.
func ChatToolsFromAnthropicTools(tools []types.AnthropicTool) []any {
	if len(tools) == 0 {
		return nil
	}
	out := make([]any, 0, len(tools))
	for _, tool := range tools {
		fn := map[string]any{
			"name":       tool.Name,
			"parameters": tool.InputSchema,
		}
		if tool.Description != "" {
			fn["description"] = tool.Description
		}
		out = append(out, map[string]any{"type": "function", "function": fn})
	}
	return out
}

func chatToolChoiceFromAnthropic(choice *types.AnthropicToolChoice) any {
	if choice == nil {
		return nil
	}
	switch choice.Type {
	case "any":
		return "required"
	case "tool":
		return map[string]any{"type": "function", "function": map[string]any{"name": choice.Name}}
	default:
		return "auto"
	}
}

// mapFinishReasonToAnthropic reverses mapStopReason for the non-streaming
// Messages envelope (the collectors report OpenAI-style finish reasons).
func mapFinishReasonToAnthropic(finishReason string) string {
	switch finishReason {
	case "length":
		return "max_tokens"
	case "content_filter":
		return types.SyntheticStopReasonContentFilter
	case "tool_calls":
		return "tool_use"
	default:
		return "end_turn"
	}
}

func normalizeAnthropicSSEStopReason(reason string) string {
	switch reason {
	case "length":
		return "max_tokens"
	case "content_filter", types.SyntheticStopReasonContentFilter:
		return types.SyntheticStopReasonContentFilter
	default:
		return reason
	}
}

// WriteMessagesResponse writes the non-streaming Messages envelope.
func WriteMessagesResponse(
	w io.Writer,
	messageID string,
	model string,
	result StreamResult,
	inputTokens int,
	outputTokens int,
) error {
	content := make([]map[string]any, 0, len(result.Thinking)+1+len(result.ToolCalls))
	// Thinking blocks come first (before text/tool_use) and carry their
	// signature — Anthropic requires them replayed verbatim on the next
	// tool-use turn when extended thinking is on.
	for _, th := range result.Thinking {
		block := map[string]any{"type": "thinking", "thinking": th.Text}
		if th.Signature != "" {
			block["signature"] = th.Signature
		}
		content = append(content, block)
	}
	// Emit a text block when the model produced text, or as the lone block
	// for a genuinely empty turn (no thinking, no tool calls).
	if result.Text != "" || (len(result.ToolCalls) == 0 && len(result.Thinking) == 0) {
		content = append(content, map[string]any{"type": "text", "text": result.Text})
	}
	for _, call := range result.ToolCalls {
		var input map[string]any
		if err := json.Unmarshal([]byte(call.Arguments), &input); err != nil || input == nil {
			input = map[string]any{}
		}
		content = append(content, map[string]any{
			"type":  "tool_use",
			"id":    call.ID,
			"name":  call.Name,
			"input": input,
		})
	}
	usageBody := map[string]any{
		"input_tokens":  inputTokens,
		"output_tokens": outputTokens,
	}
	if result.Usage != nil {
		if result.Usage.CacheReadInputTokens > 0 {
			usageBody["cache_read_input_tokens"] = result.Usage.CacheReadInputTokens
		}
		if result.Usage.CacheCreationInputTokens > 0 {
			usageBody["cache_creation_input_tokens"] = result.Usage.CacheCreationInputTokens
		}
	}
	payload := map[string]any{
		"id":            messageID,
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"content":       content,
		"stop_reason":   mapFinishReasonToAnthropic(result.FinishReason),
		"stop_sequence": nil,
		"usage":         usageBody,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// RelayAnthropicStream pipes the internal Anthropic-SSE contract out to a
// /v1/messages client, capturing text/tools/usage/stop_reason for
// settlement on the way through.
//
// Native upstream streams (anthropic-direct, bedrock) begin with
// message_start and pass through verbatim — thinking deltas and all.
// Synthetic streams from the OpenAI→Anthropic translate layer carry only
// content_block_delta / tool events / message_delta / message_stop, so
// the relay injects the framing Anthropic SDKs require (message_start,
// content_block_start/stop) and remaps block indexes so a text block and
// the first tool block don't collide on index 0.
func RelayAnthropicStream(r io.Reader, w io.Writer, messageID, model string) (StreamResult, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSEBlockBytes)
	scanner.Split(splitDoubleNewline)

	passthrough := false
	first := true
	started := false       // synthetic message_start written
	textBlockOpen := false // synthetic text block open
	nextIndex := 0
	textIndex := 0
	toolIndexMap := map[int]int{}

	finishReason := "stop"
	var captured strings.Builder
	var usage *StreamUsage
	toolCallsByIndex := map[int]*types.ToolCall{}
	var toolOrder []int

	writeEvent := func(name string, payload map[string]any) error {
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, body)
		return err
	}
	ensureStarted := func() error {
		if passthrough || started {
			return nil
		}
		started = true
		return writeEvent("message_start", map[string]any{
			"type": "message_start",
			"message": map[string]any{
				"id":            messageID,
				"type":          "message",
				"role":          "assistant",
				"model":         model,
				"content":       []any{},
				"stop_reason":   nil,
				"stop_sequence": nil,
				"usage":         map[string]int{"input_tokens": 0, "output_tokens": 0},
			},
		})
	}
	closeTextBlock := func() error {
		if !textBlockOpen {
			return nil
		}
		textBlockOpen = false
		return writeEvent("content_block_stop", map[string]any{
			"type":  "content_block_stop",
			"index": textIndex,
		})
	}

	for scanner.Scan() {
		raw := scanner.Bytes()
		eventName, dataJSON := parseSSEBlock(raw)
		if dataJSON == nil {
			continue
		}
		if first {
			first = false
			passthrough = eventName == "message_start"
		}

		// Harvest settlement data regardless of mode.
		switch eventName {
		case "message_start":
			// Route through mergeMessageStartUsage so native /v1/messages
			// streaming records the Anthropic cache convention identically to
			// the chat and non-streaming paths — otherwise a full cache hit
			// (input_tokens:0) would settle on the chars/4 estimate here.
			mergeMessageStartUsage(&usage, getMap(dataJSON, "message"))
		case "content_block_start":
			if block := getMap(dataJSON, "content_block"); block != nil && getString(block, "type") == "tool_use" {
				index := getInt(dataJSON, "index")
				if _, ok := toolCallsByIndex[index]; !ok {
					toolOrder = append(toolOrder, index)
				}
				id := getString(block, "id")
				toolCallsByIndex[index] = &types.ToolCall{ID: id, CallID: id, Name: getString(block, "name")}
			}
		case "content_block_delta":
			if delta := getMap(dataJSON, "delta"); delta != nil {
				switch getString(delta, "type") {
				case "text_delta":
					captured.WriteString(getString(delta, "text"))
				case "input_json_delta":
					if call := toolCallsByIndex[getInt(dataJSON, "index")]; call != nil {
						call.Arguments += getString(delta, "partial_json")
					}
				}
			}
		case "message_delta":
			if delta := getMap(dataJSON, "delta"); delta != nil {
				if reason := getString(delta, "stop_reason"); reason != "" {
					finishReason = mapStopReason(reason)
				}
			}
			mergeUsage(&usage, getMap(dataJSON, "usage"))
		}

		if passthrough {
			if _, err := w.Write(raw); err != nil {
				return StreamResult{}, err
			}
			if _, err := w.Write([]byte("\n\n")); err != nil {
				return StreamResult{}, err
			}
			if eventName == "message_stop" {
				return relayResult(captured.String(), finishReason, usage, toolCallsByIndex, toolOrder), nil
			}
			continue
		}

		// Synthetic mode: inject framing + remap indexes.
		switch eventName {
		case "content_block_start":
			if err := ensureStarted(); err != nil {
				return StreamResult{}, err
			}
			if err := closeTextBlock(); err != nil {
				return StreamResult{}, err
			}
			origIndex := getInt(dataJSON, "index")
			outIndex := nextIndex
			nextIndex++
			toolIndexMap[origIndex] = outIndex
			dataJSON["index"] = outIndex
			if err := writeEvent(eventName, dataJSON); err != nil {
				return StreamResult{}, err
			}
		case "content_block_delta":
			if err := ensureStarted(); err != nil {
				return StreamResult{}, err
			}
			delta := getMap(dataJSON, "delta")
			if delta != nil && getString(delta, "type") == "text_delta" {
				if !textBlockOpen {
					textBlockOpen = true
					textIndex = nextIndex
					nextIndex++
					if err := writeEvent("content_block_start", map[string]any{
						"type":          "content_block_start",
						"index":         textIndex,
						"content_block": map[string]any{"type": "text", "text": ""},
					}); err != nil {
						return StreamResult{}, err
					}
				}
				dataJSON["index"] = textIndex
			} else if mapped, ok := toolIndexMap[getInt(dataJSON, "index")]; ok {
				dataJSON["index"] = mapped
			}
			if err := writeEvent(eventName, dataJSON); err != nil {
				return StreamResult{}, err
			}
		case "content_block_stop":
			if mapped, ok := toolIndexMap[getInt(dataJSON, "index")]; ok {
				dataJSON["index"] = mapped
			}
			if err := writeEvent(eventName, dataJSON); err != nil {
				return StreamResult{}, err
			}
		case "message_delta":
			if err := ensureStarted(); err != nil {
				return StreamResult{}, err
			}
			if err := closeTextBlock(); err != nil {
				return StreamResult{}, err
			}
			if delta := getMap(dataJSON, "delta"); delta != nil {
				if reason := getString(delta, "stop_reason"); reason != "" {
					delta["stop_reason"] = normalizeAnthropicSSEStopReason(reason)
				}
			}
			if err := writeEvent(eventName, dataJSON); err != nil {
				return StreamResult{}, err
			}
		case "message_stop":
			if err := ensureStarted(); err != nil {
				return StreamResult{}, err
			}
			if err := closeTextBlock(); err != nil {
				return StreamResult{}, err
			}
			if err := writeEvent(eventName, dataJSON); err != nil {
				return StreamResult{}, err
			}
			return relayResult(captured.String(), finishReason, usage, toolCallsByIndex, toolOrder), nil
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return StreamResult{}, err
	}
	return relayResult(captured.String(), finishReason, usage, toolCallsByIndex, toolOrder), nil
}

func relayResult(
	text string,
	finishReason string,
	usage *StreamUsage,
	toolCallsByIndex map[int]*types.ToolCall,
	toolOrder []int,
) StreamResult {
	return StreamResult{
		Text:         text,
		FinishReason: finishReason,
		Usage:        usage,
		ToolCalls:    orderedToolCalls(toolCallsByIndex, toolOrder),
	}
}
