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

const TrustedRouterWebSearchFunction = "_trustedrouter_web_search"

func RejectUnsupportedResponsesFields(raw map[string]json.RawMessage) error {
	return validateResponsesFields(raw, supportedResponsesCreateFields)
}

func RejectUnsupportedResponsesInputTokenFields(raw map[string]json.RawMessage) error {
	return validateResponsesFields(raw, supportedResponsesInputTokenFields)
}

var supportedResponsesCreateFields = map[string]struct{}{
	"background":             {},
	"conversation":           {},
	"include":                {},
	"input":                  {},
	"instructions":           {},
	"max_output_tokens":      {},
	"max_tokens":             {},
	"max_tool_calls":         {},
	"metadata":               {},
	"modalities":             {},
	"model":                  {},
	"models":                 {},
	"n":                      {},
	"parallel_tool_calls":    {},
	"previous_response_id":   {},
	"prompt":                 {},
	"prompt_cache_key":       {},
	"prompt_cache_retention": {},
	"provider":               {},
	"reasoning":              {},
	"safety_identifier":      {},
	"service_tier":           {},
	"session_id":             {},
	"store":                  {},
	"stream":                 {},
	"stream_options":         {},
	"temperature":            {},
	"tags":                   {},
	"text":                   {},
	"tool_choice":            {},
	"tools":                  {},
	"top_logprobs":           {},
	"top_p":                  {},
	"trace":                  {},
	"truncation":             {},
	"user":                   {},
}

var supportedResponsesInputTokenFields = map[string]struct{}{
	"conversation":           {},
	"input":                  {},
	"instructions":           {},
	"model":                  {},
	"models":                 {},
	"parallel_tool_calls":    {},
	"previous_response_id":   {},
	"prompt":                 {},
	"prompt_cache_key":       {},
	"prompt_cache_retention": {},
	"reasoning":              {},
	"text":                   {},
	"tool_choice":            {},
	"tools":                  {},
	"truncation":             {},
}

func validateResponsesFields(raw map[string]json.RawMessage, allowed map[string]struct{}) error {
	for key, value := range raw {
		if _, ok := allowed[key]; !ok && presentNonNull(value) {
			return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: key}
		}
	}
	for _, field := range []string{"conversation", "previous_response_id", "prompt"} {
		if value, ok := raw[field]; ok && presentNonNull(value) {
			return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: field}
		}
	}
	if boolField(raw, "store") {
		return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "store=true"}
	}
	if boolField(raw, "background") {
		return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "background=true"}
	}
	if value, ok := raw["prompt_cache_retention"]; ok && presentNonNull(value) {
		return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "prompt_cache_retention"}
	}
	if value, ok := raw["reasoning"]; ok {
		if err := validateReasoningConfig(value); err != nil {
			return err
		}
	}
	if value, ok := raw["include"]; ok {
		if err := validateResponsesInclude(value); err != nil {
			return err
		}
	}
	if value, ok := raw["modalities"]; ok {
		if err := validateTextModalities(value); err != nil {
			return err
		}
	}
	if value, ok := raw["input"]; ok {
		if err := validateResponsesInput(value); err != nil {
			return err
		}
	}
	if value, ok := raw["text"]; ok {
		if err := validateTextConfig(value); err != nil {
			return err
		}
	}
	if value, ok := raw["tools"]; ok {
		if err := validateResponsesTools(value); err != nil {
			return err
		}
	}
	if value, ok := raw["max_tool_calls"]; ok && presentNonNull(value) {
		if err := validateResponsesMaxToolCalls(value, raw["tools"]); err != nil {
			return err
		}
	}
	if value, ok := raw["tool_choice"]; ok {
		if err := validateResponsesToolChoice(value); err != nil {
			return err
		}
	}
	if value, ok := raw["top_logprobs"]; ok && presentNonNull(value) {
		return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "top_logprobs"}
	}
	if value, ok := raw["truncation"]; ok {
		if err := validateTruncation(value); err != nil {
			return err
		}
	}
	if value, ok := raw["stream_options"]; ok {
		var options map[string]any
		if err := json.Unmarshal(value, &options); err != nil && presentNonNull(value) {
			return &AdapterError{Status: 400, Message: "stream_options must be an object", Context: "stream_options"}
		}
	}
	return nil
}

func ResponsesToChat(req *types.OpenAIResponsesRequest) (*types.OpenAIChatRequest, error) {
	if strings.TrimSpace(req.Model) == "" {
		return nil, &AdapterError{Status: 400, Message: "model is required"}
	}
	responseFormat, err := chatResponseFormatFromResponsesText(req.Text)
	if err != nil {
		return nil, err
	}
	tools, err := ChatToolsFromResponsesTools(req.Tools)
	if err != nil {
		return nil, err
	}
	toolChoice, err := ChatToolChoiceFromResponses(req.ToolChoice)
	if err != nil {
		return nil, err
	}
	webSearch, err := ResponsesWebSearchConfig(req.Tools, req.MaxToolCalls, req.Include)
	if err != nil {
		return nil, err
	}
	messages := make([]types.OpenAIChatMessage, 0, 4)
	if strings.TrimSpace(req.Instructions) != "" {
		messages = append(messages, types.OpenAIChatMessage{
			Role:    "system",
			Content: req.Instructions,
		})
	}
	inputMessages, err := responseInputMessages(req.Input)
	if err != nil {
		return nil, err
	}
	messages = append(messages, inputMessages...)
	if len(messages) == 0 {
		return nil, &AdapterError{Status: 400, Message: "input must contain text"}
	}
	maxTokens := req.MaxOutputTokens
	if maxTokens == nil {
		maxTokens = req.MaxTokens
	}
	return &types.OpenAIChatRequest{
		Model:          req.Model,
		Models:         req.Models,
		Messages:       messages,
		Stream:         req.Stream,
		Temperature:    req.Temperature,
		TopP:           req.TopP,
		MaxTokens:      maxTokens,
		N:              req.N,
		Provider:       req.Provider,
		Metadata:       req.Metadata,
		Trace:          req.Trace,
		User:           req.User,
		SessionID:      req.SessionID,
		Tags:           types.CloneRequestTags(req.Tags),
		ResponseFormat: responseFormat,
		Tools:          tools,
		ToolChoice:     toolChoice,
		ParallelTools:  req.ParallelToolCalls,
		Reasoning:      req.Reasoning,
		Response: &types.ResponseRequestMeta{
			Include:              req.Include,
			Modalities:           req.Modalities,
			ParallelToolCalls:    req.ParallelToolCalls,
			PromptCacheKey:       req.PromptCacheKey,
			SafetyIdentifier:     req.SafetyIdentifier,
			ServiceTier:          req.ServiceTier,
			StreamOptions:        req.StreamOptions,
			Text:                 req.Text,
			InputModalities:      types.RequestInputModalities(&types.OpenAIChatRequest{Messages: messages}),
			ToolChoice:           req.ToolChoice,
			Tools:                req.Tools,
			TopLogprobs:          req.TopLogprobs,
			Truncation:           req.Truncation,
			MaxOutputTokens:      req.MaxOutputTokens,
			MaxToolCalls:         req.MaxToolCalls,
			PromptCacheRetention: req.PromptCacheRetention,
			Reasoning:            req.Reasoning,
			Store:                false,
			WebSearch:            webSearch,
		},
	}, nil
}

func responseInputMessages(input any) ([]types.OpenAIChatMessage, error) {
	switch value := input.(type) {
	case string:
		if strings.TrimSpace(value) == "" {
			return nil, &AdapterError{Status: 400, Message: "input must contain text"}
		}
		return []types.OpenAIChatMessage{{Role: "user", Content: value}}, nil
	case []any:
		out := make([]types.OpenAIChatMessage, 0, len(value))
		for index, item := range value {
			message, err := responseInputMessage(item, index)
			if err != nil {
				return nil, err
			}
			out = append(out, message)
		}
		return out, nil
	case map[string]any:
		message, err := responseInputMessage(value, 0)
		if err != nil {
			return nil, err
		}
		return []types.OpenAIChatMessage{message}, nil
	default:
		return nil, &AdapterError{Status: 400, Message: "input must be text or text messages"}
	}
}

func responseInputMessage(item any, index int) (types.OpenAIChatMessage, error) {
	if text, ok := item.(string); ok {
		return types.OpenAIChatMessage{Role: "user", Content: text}, nil
	}
	m, ok := item.(map[string]any)
	if !ok {
		return types.OpenAIChatMessage{}, &AdapterError{
			Status:  400,
			Message: "input item must be text or object",
			Context: fmt.Sprintf("input[%d]", index),
		}
	}
	switch stringValue(m["type"]) {
	case "function_call":
		return responseFunctionCallMessage(m, index)
	case "function_call_output":
		return responseFunctionCallOutputMessage(m, index)
	}
	role := stringValue(m["role"])
	if role == "" {
		role = "user"
	}
	if role == "developer" {
		role = "system"
	}
	if role != "system" && role != "user" && role != "assistant" {
		return types.OpenAIChatMessage{}, &AdapterError{Status: 400, Message: "unsupported input role"}
	}
	content, err := responseContent(m)
	if err != nil {
		return types.OpenAIChatMessage{}, err
	}
	if types.ContentEmpty(content) {
		return types.OpenAIChatMessage{}, &AdapterError{Status: 400, Message: "input item must contain text or image"}
	}
	return types.OpenAIChatMessage{Role: role, Content: content}, nil
}

func responseFunctionCallMessage(m map[string]any, index int) (types.OpenAIChatMessage, error) {
	callID := strings.TrimSpace(stringValue(m["call_id"]))
	if callID == "" {
		return types.OpenAIChatMessage{}, &AdapterError{
			Status: 400, Message: "function_call call_id is required", Context: fmt.Sprintf("input[%d].call_id", index),
		}
	}
	name := strings.TrimSpace(stringValue(m["name"]))
	if name == "" {
		return types.OpenAIChatMessage{}, &AdapterError{
			Status: 400, Message: "function_call name is required", Context: fmt.Sprintf("input[%d].name", index),
		}
	}
	arguments, ok := m["arguments"].(string)
	if !ok && m["arguments"] != nil {
		return types.OpenAIChatMessage{}, &AdapterError{
			Status: 400, Message: "function_call arguments must be a JSON string", Context: fmt.Sprintf("input[%d].arguments", index),
		}
	}
	if strings.TrimSpace(arguments) == "" {
		arguments = "{}"
	}
	if !json.Valid([]byte(arguments)) {
		return types.OpenAIChatMessage{}, &AdapterError{
			Status: 400, Message: "function_call arguments must contain valid JSON", Context: fmt.Sprintf("input[%d].arguments", index),
		}
	}
	return types.OpenAIChatMessage{
		Role:    "assistant",
		Content: "",
		ToolCalls: []types.OpenAIToolCall{{
			ID:   callID,
			Type: "function",
			Function: types.OpenAIToolFunction{
				Name:      name,
				Arguments: arguments,
			},
		}},
	}, nil
}

func responseFunctionCallOutputMessage(m map[string]any, index int) (types.OpenAIChatMessage, error) {
	callID := strings.TrimSpace(stringValue(m["call_id"]))
	if callID == "" {
		return types.OpenAIChatMessage{}, &AdapterError{
			Status: 400, Message: "function_call_output call_id is required", Context: fmt.Sprintf("input[%d].call_id", index),
		}
	}
	outputValue, ok := m["output"]
	if !ok {
		return types.OpenAIChatMessage{}, &AdapterError{
			Status: 400, Message: "function_call_output output is required", Context: fmt.Sprintf("input[%d].output", index),
		}
	}
	output, err := responseFunctionCallOutput(outputValue, index)
	if err != nil {
		return types.OpenAIChatMessage{}, err
	}
	return types.OpenAIChatMessage{Role: "tool", Content: output, ToolCallID: callID}, nil
}

func responseFunctionCallOutput(value any, index int) (any, error) {
	switch output := value.(type) {
	case nil:
		return "", nil
	case string:
		return output, nil
	case []any:
		content, err := responseContent(map[string]any{"content": output})
		if err != nil {
			return nil, err
		}
		return content, nil
	default:
		return nil, &AdapterError{
			Status: 400, Message: "function_call_output output must be text or content parts", Context: fmt.Sprintf("input[%d].output", index),
		}
	}
}

func responseContent(m map[string]any) (any, error) {
	if text := stringValue(m["text"]); text != "" {
		return text, nil
	}
	switch content := m["content"].(type) {
	case string:
		return content, nil
	case []any:
		parts := make([]types.ChatContentPart, 0, len(content))
		onlyText := true
		for _, item := range content {
			part, ok := item.(map[string]any)
			if !ok {
				return "", &AdapterError{Status: 400, Message: "content part must be text object"}
			}
			partType := stringValue(part["type"])
			switch partType {
			case "", "text", "input_text":
				if text := stringValue(part["text"]); text != "" {
					parts = append(parts, types.ChatContentPart{Type: "text", Text: text})
				}
			case "input_image", "image_url":
				imagePart, err := imageContentPart(part)
				if err != nil {
					return "", err
				}
				parts = append(parts, imagePart)
				onlyText = false
			case "input_file", "file", "input_audio", "audio", "input_video", "video":
				return "", &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: partType}
			default:
				return "", &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "content"}
			}
		}
		if onlyText {
			textParts := make([]string, 0, len(parts))
			for _, part := range parts {
				if part.Text != "" {
					textParts = append(textParts, part.Text)
				}
			}
			return strings.Join(textParts, "\n"), nil
		}
		return parts, nil
	default:
		return "", &AdapterError{Status: 400, Message: "input item must contain text or image"}
	}
}

func imageContentPart(part map[string]any) (types.ChatContentPart, error) {
	if fileID := stringValue(part["file_id"]); fileID != "" {
		return types.ChatContentPart{}, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "input_image.file_id"}
	}
	imageURL, detail := imageURLAndDetail(part)
	if strings.TrimSpace(imageURL) == "" {
		return types.ChatContentPart{}, &AdapterError{Status: 400, Message: "input_image.image_url is required", Context: "input_image.image_url"}
	}
	detail, err := normalizeImageDetail(detail)
	if err != nil {
		return types.ChatContentPart{}, err
	}
	return types.ChatContentPart{
		Type: "image_url",
		ImageURL: &types.ChatImageURL{
			URL:    imageURL,
			Detail: detail,
		},
	}, nil
}

func imageURLAndDetail(part map[string]any) (string, string) {
	detail := stringValue(part["detail"])
	switch value := part["image_url"].(type) {
	case string:
		return value, detail
	case map[string]any:
		if detail == "" {
			detail = stringValue(value["detail"])
		}
		return stringValue(value["url"]), detail
	default:
		return "", detail
	}
}

func normalizeImageDetail(detail string) (string, error) {
	detail = strings.ToLower(strings.TrimSpace(detail))
	if detail == "" {
		return "auto", nil
	}
	switch detail {
	case "auto", "low", "high", "original":
		return detail, nil
	default:
		return "", &AdapterError{Status: 400, Message: "invalid image detail", Context: "input_image.detail"}
	}
}

func CollectAnthropicText(r io.Reader) (StreamResult, error) {
	return CollectAnthropicTextWithObserver(r, nil)
}

func CollectAnthropicTextWithObserver(r io.Reader, observer StreamObserver) (StreamResult, error) {
	finishReason := "stop"
	var captured strings.Builder
	var usage *StreamUsage
	toolCallsByIndex := map[int]*types.ToolCall{}
	var toolOrder []int
	thinkingByIndex := map[int]*ThinkingBlock{}
	var thinkingOrder []int
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSEBlockBytes)
	scanner.Split(splitDoubleNewline)
	for scanner.Scan() {
		eventName, dataJSON := parseSSEBlock(scanner.Bytes())
		if dataJSON == nil {
			continue
		}
		switch eventName {
		case "message_start":
			mergeMessageStartUsage(&usage, getMap(dataJSON, "message"))
		case "content_block_start":
			block := getMap(dataJSON, "content_block")
			if block != nil && getString(block, "type") == "tool_use" {
				index := getInt(dataJSON, "index")
				if _, ok := toolCallsByIndex[index]; !ok {
					toolOrder = append(toolOrder, index)
				}
				id := getString(block, "id")
				toolCallsByIndex[index] = &types.ToolCall{
					ID:     id,
					CallID: id,
					Name:   getString(block, "name"),
				}
			} else if block != nil && getString(block, "type") == "thinking" {
				index := getInt(dataJSON, "index")
				if _, ok := thinkingByIndex[index]; !ok {
					thinkingOrder = append(thinkingOrder, index)
				}
				thinkingByIndex[index] = &ThinkingBlock{
					Text:      getString(block, "thinking"),
					Signature: getString(block, "signature"),
				}
			}
		case "content_block_delta":
			delta := getMap(dataJSON, "delta")
			if delta != nil && getString(delta, "type") == "text_delta" {
				text := getString(delta, "text")
				captured.WriteString(text)
				if observer != nil && text != "" {
					observer(StreamDelta{Type: "text_delta", Index: getInt(dataJSON, "index"), Text: text})
				}
			} else if delta != nil && getString(delta, "type") == "input_json_delta" {
				index := getInt(dataJSON, "index")
				call := toolCallsByIndex[index]
				if call != nil {
					partial := getString(delta, "partial_json")
					call.Arguments += partial
					if observer != nil && partial != "" {
						observer(StreamDelta{Type: "input_json_delta", Index: index, Text: partial})
					}
				}
			} else if delta != nil && getString(delta, "type") == "thinking_delta" {
				index := getInt(dataJSON, "index")
				text := getString(delta, "thinking")
				if tb := thinkingByIndex[index]; tb != nil {
					tb.Text += text
				}
				if observer != nil && text != "" {
					observer(StreamDelta{Type: "thinking_delta", Index: index, Text: text})
				}
			} else if delta != nil && getString(delta, "type") == "signature_delta" {
				index := getInt(dataJSON, "index")
				signature := getString(delta, "signature")
				if tb := thinkingByIndex[index]; tb != nil {
					tb.Signature += signature
				}
				if observer != nil && signature != "" {
					observer(StreamDelta{Type: "signature_delta", Index: index, Signature: signature})
				}
			}
		case "message_delta":
			if delta := getMap(dataJSON, "delta"); delta != nil {
				if reason := getString(delta, "stop_reason"); reason != "" {
					finishReason = mapStopReason(reason)
				}
			}
			mergeUsage(&usage, getMap(dataJSON, "usage"))
		case "message_stop":
			return StreamResult{Text: captured.String(), FinishReason: finishReason, ToolCalls: orderedToolCalls(toolCallsByIndex, toolOrder), Thinking: orderedThinking(thinkingByIndex, thinkingOrder), Usage: usage}, nil
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return StreamResult{}, err
	}
	return StreamResult{Text: captured.String(), FinishReason: finishReason, ToolCalls: orderedToolCalls(toolCallsByIndex, toolOrder), Thinking: orderedThinking(thinkingByIndex, thinkingOrder), Usage: usage}, nil
}

func WriteResponsesResponse(
	w io.Writer,
	responseID string,
	model string,
	text string,
	toolCalls []types.ToolCall,
	inputTokens int,
	outputTokens int,
	usage *StreamUsage,
	created int64,
	textConfig map[string]any,
	meta *types.ResponseRequestMeta,
) error {
	cachedTokens, cacheCreationTokens, reasoningTokens := 0, 0, 0
	inputExcludesCache := false
	if usage != nil {
		cachedTokens = usage.CacheReadInputTokens
		cacheCreationTokens = usage.CacheCreationInputTokens
		reasoningTokens = usage.ReasoningTokens
		inputExcludesCache = usage.InputExcludesCache
	}
	// Fold Anthropic's cache tokens back into the prompt total so input_tokens is
	// the FULL prompt with input_tokens_details.cached_tokens as a subset — the
	// same accounting chatCompletionUsage applies. Without this a full cache hit
	// (real input_tokens:0 from realOrEstimatedTokens) would report input_tokens:0
	// with a positive cached_tokens and a total that excludes the prompt.
	promptTokens := foldedPromptTokens(inputTokens, cachedTokens, cacheCreationTokens, inputExcludesCache)
	payload := responsesObject(responseID, model, text, toolCalls, promptTokens, outputTokens, cachedTokens, reasoningTokens, created, "completed", textConfig, meta)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func WriteResponsesInputTokens(w io.Writer, inputTokens int) error {
	payload := map[string]any{
		"object":       "response.input_tokens",
		"input_tokens": inputTokens,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func NormalizeResponsesStructuredOutput(text string, textConfig map[string]any) (string, error) {
	formatType := responsesTextFormatType(textConfig)
	if formatType != "json_object" && formatType != "json_schema" {
		return text, nil
	}
	normalized, ok := normalizeJSONString(strings.TrimSpace(text), formatType)
	if ok {
		return normalized, nil
	}
	extracted, ok := extractFirstJSONValue(text, formatType)
	if ok {
		return extracted, nil
	}
	return "", &AdapterError{Status: 502, Message: "provider did not return valid JSON", Context: "text.format"}
}

func TransformResponsesStream(
	r io.Reader,
	w io.Writer,
	responseID string,
	model string,
	inputTokens int,
	textConfig map[string]any,
	meta *types.ResponseRequestMeta,
) (StreamResult, error) {
	created := time.Now().Unix()
	messageID := "msg_" + strings.TrimPrefix(responseID, "resp_")
	finishReason := "stop"
	var captured strings.Builder
	var reasoningCaptured strings.Builder
	toolCallsByIndex := map[int]*types.ToolCall{}
	var toolOrder []int
	toolOutputIndexes := map[int]int{}
	toolDone := map[int]bool{}
	thinkingByIndex := map[int]*ThinkingBlock{}
	var thinkingOrder []int
	seq := 0
	if err := writeResponseEventSeq(w, &seq, "response.created", map[string]any{
		"type":     "response.created",
		"response": responsesObject(responseID, model, "", nil, inputTokens, 0, 0, 0, created, "in_progress", textConfig, meta),
	}); err != nil {
		return StreamResult{}, err
	}
	if err := writeResponseEventSeq(w, &seq, "response.in_progress", map[string]any{
		"type":     "response.in_progress",
		"response": responsesObject(responseID, model, "", nil, inputTokens, 0, 0, 0, created, "in_progress", textConfig, meta),
	}); err != nil {
		return StreamResult{}, err
	}
	nextOutputIndex := 0
	messageOutputIndex := 0
	messageStarted := false
	reasoningID := "rs_" + strings.TrimPrefix(responseID, "resp_")
	reasoningOutputIndex := 0
	reasoningStarted := false
	startMessage := func() error {
		if messageStarted {
			return nil
		}
		messageOutputIndex = nextOutputIndex
		nextOutputIndex++
		messageStarted = true
		if err := writeResponseEventSeq(w, &seq, "response.output_item.added", map[string]any{
			"type":         "response.output_item.added",
			"output_index": messageOutputIndex,
			"item": map[string]any{
				"id":      messageID,
				"type":    "message",
				"status":  "in_progress",
				"role":    "assistant",
				"content": []any{},
			},
		}); err != nil {
			return err
		}
		return writeResponseEventSeq(w, &seq, "response.content_part.added", map[string]any{
			"type":          "response.content_part.added",
			"item_id":       messageID,
			"output_index":  messageOutputIndex,
			"content_index": 0,
			"part":          map[string]any{"type": "output_text", "text": "", "annotations": []any{}},
		})
	}
	startReasoning := func() error {
		if reasoningStarted {
			return nil
		}
		reasoningOutputIndex = nextOutputIndex
		nextOutputIndex++
		reasoningStarted = true
		if err := writeResponseEventSeq(w, &seq, "response.output_item.added", map[string]any{
			"type":         "response.output_item.added",
			"response_id":  responseID,
			"output_index": reasoningOutputIndex,
			"item": map[string]any{
				"id":      reasoningID,
				"type":    "reasoning",
				"status":  "in_progress",
				"summary": []any{},
			},
		}); err != nil {
			return err
		}
		return writeResponseEventSeq(w, &seq, "response.content_part.added", map[string]any{
			"type":          "response.content_part.added",
			"item_id":       reasoningID,
			"output_index":  reasoningOutputIndex,
			"content_index": 0,
			"part":          map[string]any{"type": "reasoning_text", "text": ""},
		})
	}
	finishReasoning := func() error {
		if !reasoningStarted {
			return nil
		}
		text := reasoningCaptured.String()
		if err := writeResponseEventSeq(w, &seq, "response.reasoning_text.done", map[string]any{
			"type":          "response.reasoning_text.done",
			"item_id":       reasoningID,
			"output_index":  reasoningOutputIndex,
			"content_index": 0,
			"text":          text,
		}); err != nil {
			return err
		}
		if err := writeResponseEventSeq(w, &seq, "response.content_part.done", map[string]any{
			"type":          "response.content_part.done",
			"item_id":       reasoningID,
			"output_index":  reasoningOutputIndex,
			"content_index": 0,
			"part":          map[string]any{"type": "reasoning_text", "text": text},
		}); err != nil {
			return err
		}
		return writeResponseEventSeq(w, &seq, "response.output_item.done", map[string]any{
			"type":         "response.output_item.done",
			"response_id":  responseID,
			"output_index": reasoningOutputIndex,
			"item": map[string]any{
				"id":      reasoningID,
				"type":    "reasoning",
				"status":  "completed",
				"summary": []map[string]any{{"type": "reasoning_text", "text": text}},
			},
		})
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSEBlockBytes)
	scanner.Split(splitDoubleNewline)
	for scanner.Scan() {
		eventName, dataJSON := parseSSEBlock(scanner.Bytes())
		if dataJSON == nil {
			continue
		}
		switch eventName {
		case "content_block_start":
			block := getMap(dataJSON, "content_block")
			if block == nil {
				continue
			}
			if getString(block, "type") == "thinking" {
				blockIndex := getInt(dataJSON, "index")
				if _, ok := thinkingByIndex[blockIndex]; !ok {
					thinkingOrder = append(thinkingOrder, blockIndex)
				}
				thinkingByIndex[blockIndex] = &ThinkingBlock{
					Text:      getString(block, "thinking"),
					Signature: getString(block, "signature"),
				}
				if err := startReasoning(); err != nil {
					return StreamResult{}, err
				}
				continue
			}
			if getString(block, "type") != "tool_use" {
				continue
			}
			blockIndex := getInt(dataJSON, "index")
			if _, ok := toolCallsByIndex[blockIndex]; !ok {
				toolOrder = append(toolOrder, blockIndex)
			}
			id := getString(block, "id")
			call := &types.ToolCall{
				ID:     id,
				CallID: id,
				Name:   getString(block, "name"),
			}
			toolCallsByIndex[blockIndex] = call
			outputIndex := nextOutputIndex
			nextOutputIndex++
			toolOutputIndexes[blockIndex] = outputIndex
			if err := writeResponseEventSeq(w, &seq, "response.output_item.added", map[string]any{
				"type":         "response.output_item.added",
				"response_id":  responseID,
				"output_index": outputIndex,
				"item": map[string]any{
					"id":        call.ID,
					"type":      "function_call",
					"status":    "in_progress",
					"call_id":   call.CallID,
					"name":      call.Name,
					"arguments": "",
				},
			}); err != nil {
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
				if err := startMessage(); err != nil {
					return StreamResult{}, err
				}
				captured.WriteString(deltaText)
				if err := writeResponseEventSeq(w, &seq, "response.output_text.delta", map[string]any{
					"type":          "response.output_text.delta",
					"item_id":       messageID,
					"output_index":  messageOutputIndex,
					"content_index": 0,
					"delta":         deltaText,
				}); err != nil {
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
				if err := startReasoning(); err != nil {
					return StreamResult{}, err
				}
				reasoningCaptured.WriteString(deltaText)
				if err := writeResponseEventSeq(w, &seq, "response.reasoning_text.delta", map[string]any{
					"type":          "response.reasoning_text.delta",
					"item_id":       reasoningID,
					"output_index":  reasoningOutputIndex,
					"content_index": 0,
					"delta":         deltaText,
				}); err != nil {
					return StreamResult{}, err
				}
			case "signature_delta":
				blockIndex := getInt(dataJSON, "index")
				if tb := thinkingByIndex[blockIndex]; tb != nil {
					tb.Signature += getString(delta, "signature")
				}
			case "input_json_delta":
				blockIndex := getInt(dataJSON, "index")
				call := toolCallsByIndex[blockIndex]
				if call == nil {
					continue
				}
				deltaText := getString(delta, "partial_json")
				call.Arguments += deltaText
				if err := writeResponseEventSeq(w, &seq, "response.function_call_arguments.delta", map[string]any{
					"type":         "response.function_call_arguments.delta",
					"response_id":  responseID,
					"item_id":      call.ID,
					"output_index": toolOutputIndexes[blockIndex],
					"delta":        deltaText,
				}); err != nil {
					return StreamResult{}, err
				}
			}
		case "content_block_stop":
			blockIndex := getInt(dataJSON, "index")
			call := toolCallsByIndex[blockIndex]
			if call == nil || toolDone[blockIndex] {
				continue
			}
			toolDone[blockIndex] = true
			outputIndex := toolOutputIndexes[blockIndex]
			if err := writeResponseEventSeq(w, &seq, "response.function_call_arguments.done", map[string]any{
				"type":         "response.function_call_arguments.done",
				"response_id":  responseID,
				"item_id":      call.ID,
				"output_index": outputIndex,
				"arguments":    call.Arguments,
			}); err != nil {
				return StreamResult{}, err
			}
			if err := writeResponseEventSeq(w, &seq, "response.output_item.done", map[string]any{
				"type":         "response.output_item.done",
				"response_id":  responseID,
				"output_index": outputIndex,
				"item":         responseFunctionCallItem(responseID, outputIndex, *call),
			}); err != nil {
				return StreamResult{}, err
			}
		case "message_delta":
			if delta := getMap(dataJSON, "delta"); delta != nil {
				if reason := getString(delta, "stop_reason"); reason != "" {
					finishReason = mapStopReason(reason)
				}
			}
		case "message_stop":
			toolCalls := orderedToolCalls(toolCallsByIndex, toolOrder)
			if err := finishReasoning(); err != nil {
				return StreamResult{}, err
			}
			if !messageStarted && len(toolCalls) == 0 {
				if err := startMessage(); err != nil {
					return StreamResult{}, err
				}
			}
			return finishResponsesStream(w, &seq, responseID, messageID, model, captured.String(), toolCalls, orderedThinking(thinkingByIndex, thinkingOrder), inputTokens, created, finishReason, textConfig, meta, messageStarted, messageOutputIndex)
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return StreamResult{}, err
	}
	toolCalls := orderedToolCalls(toolCallsByIndex, toolOrder)
	if err := finishReasoning(); err != nil {
		return StreamResult{}, err
	}
	if !messageStarted && len(toolCalls) == 0 {
		if err := startMessage(); err != nil {
			return StreamResult{}, err
		}
	}
	return finishResponsesStream(w, &seq, responseID, messageID, model, captured.String(), toolCalls, orderedThinking(thinkingByIndex, thinkingOrder), inputTokens, created, finishReason, textConfig, meta, messageStarted, messageOutputIndex)
}

func finishResponsesStream(
	w io.Writer,
	seq *int,
	responseID string,
	messageID string,
	model string,
	text string,
	toolCalls []types.ToolCall,
	thinking []ThinkingBlock,
	inputTokens int,
	created int64,
	finishReason string,
	textConfig map[string]any,
	meta *types.ResponseRequestMeta,
	messageStarted bool,
	messageOutputIndex int,
) (StreamResult, error) {
	outputTokens := estimateTextTokens(ResponsesOutputForUsage(StreamResult{Text: text, ToolCalls: toolCalls}))
	events := []struct {
		name string
		body map[string]any
	}{}
	if messageStarted {
		events = append(events, []struct {
			name string
			body map[string]any
		}{
			{"response.output_text.done", map[string]any{
				"type":          "response.output_text.done",
				"item_id":       messageID,
				"output_index":  messageOutputIndex,
				"content_index": 0,
				"text":          text,
			}},
			{"response.content_part.done", map[string]any{
				"type":          "response.content_part.done",
				"item_id":       messageID,
				"output_index":  messageOutputIndex,
				"content_index": 0,
				"part":          map[string]any{"type": "output_text", "text": text, "annotations": []any{}},
			}},
			{"response.output_item.done", map[string]any{
				"type":         "response.output_item.done",
				"output_index": messageOutputIndex,
				"item": map[string]any{
					"id":      messageID,
					"type":    "message",
					"status":  "completed",
					"role":    "assistant",
					"content": []map[string]any{{"type": "output_text", "text": text, "annotations": []any{}}},
				},
			}},
		}...)
	}
	events = append(events, struct {
		name string
		body map[string]any
	}{"response.completed", map[string]any{
		"type":     "response.completed",
		"response": responsesObject(responseID, model, text, toolCalls, inputTokens, outputTokens, 0, 0, created, "completed", textConfig, meta),
	}})
	for _, event := range events {
		if err := writeResponseEventSeq(w, seq, event.name, event.body); err != nil {
			return StreamResult{}, err
		}
	}
	_, err := w.Write([]byte("data: [DONE]\n\n"))
	return StreamResult{Text: text, FinishReason: finishReason, ToolCalls: toolCalls, Thinking: thinking}, err
}

func responsesObject(
	responseID, model, text string,
	toolCalls []types.ToolCall,
	inputTokens, outputTokens int,
	cachedTokens, reasoningTokens int,
	created int64,
	status string,
	textConfig map[string]any,
	meta *types.ResponseRequestMeta,
) map[string]any {
	messageID := "msg_" + strings.TrimPrefix(responseID, "resp_")
	output := []map[string]any{}
	usage := any(nil)
	completedAt := any(nil)
	if status == "completed" {
		if meta != nil {
			for _, call := range meta.WebSearchCalls {
				output = append(output, responseWebSearchCallItem(call, meta.WebSearch != nil && meta.WebSearch.IncludeSources))
			}
		}
		if text != "" || len(toolCalls) == 0 {
			annotations := []map[string]any{}
			if meta != nil && len(meta.OutputAnnotations) > 0 {
				annotations = meta.OutputAnnotations
			}
			output = append(output, map[string]any{
				"id":     messageID,
				"type":   "message",
				"status": "completed",
				"role":   "assistant",
				"content": []map[string]any{{
					"type":        "output_text",
					"text":        text,
					"annotations": annotations,
				}},
			})
		}
		for index, call := range toolCalls {
			output = append(output, responseFunctionCallItem(responseID, index, call))
		}
		completedAt = created
		usage = map[string]any{
			"input_tokens": inputTokens,
			"input_tokens_details": map[string]any{
				"cached_tokens": cachedTokens,
			},
			"output_tokens": outputTokens,
			"output_tokens_details": map[string]any{
				"reasoning_tokens": reasoningTokens,
			},
			"total_tokens": inputTokens + outputTokens,
		}
	}
	payload := map[string]any{
		"id":                   responseID,
		"object":               "response",
		"created_at":           created,
		"completed_at":         completedAt,
		"status":               status,
		"error":                nil,
		"incomplete_details":   nil,
		"instructions":         nil,
		"max_output_tokens":    nil,
		"model":                model,
		"output":               output,
		"parallel_tool_calls":  responseParallelToolCalls(meta),
		"previous_response_id": nil,
		"reasoning": map[string]any{
			"effort":  nil,
			"summary": nil,
		},
		"store":       false,
		"temperature": 1,
		"text":        responseTextConfig(textConfig),
		"tool_choice": responseToolChoice(meta),
		"tools":       responseTools(meta),
		"top_p":       1,
		"truncation":  "disabled",
		"usage":       usage,
	}
	if status == "completed" && meta != nil && len(meta.OpenRouterMetadata) > 0 {
		payload["openrouter_metadata"] = meta.OpenRouterMetadata
	}
	return payload
}

func responseWebSearchCallItem(call types.ResponseWebSearchCall, includeSources bool) map[string]any {
	action := map[string]any{
		"type":  "search",
		"query": call.Query,
	}
	if includeSources {
		sources := make([]map[string]any, 0, len(call.Sources))
		for _, source := range call.Sources {
			sources = append(sources, map[string]any{
				"type":  "url",
				"url":   source.URL,
				"title": source.Title,
			})
		}
		action["sources"] = sources
	}
	return map[string]any{
		"id":     call.ID,
		"type":   "web_search_call",
		"status": "completed",
		"action": action,
	}
}

// BuildResponsesObject exposes the canonical response shaper to enclave-owned
// hosted tools without duplicating the Responses compatibility envelope.
func BuildResponsesObject(
	responseID, model, text string,
	toolCalls []types.ToolCall,
	inputTokens, outputTokens int,
	cachedTokens, reasoningTokens int,
	created int64,
	status string,
	textConfig map[string]any,
	meta *types.ResponseRequestMeta,
) map[string]any {
	return responsesObject(responseID, model, text, toolCalls, inputTokens, outputTokens, cachedTokens, reasoningTokens, created, status, textConfig, meta)
}

// WriteResponsesEvent writes one OpenAI Responses SSE event with a monotonic
// sequence number. The payload must not contain prompt or search-result text
// except for explicit client-facing output deltas.
func WriteResponsesEvent(w io.Writer, sequence *int, event string, payload map[string]any) error {
	return writeResponseEventSeq(w, sequence, event, payload)
}

// ResponseWebSearchCallItem returns the public OpenAI-compatible item used by
// both buffered and streaming Responses output.
func ResponseWebSearchCallItem(call types.ResponseWebSearchCall, includeSources bool) map[string]any {
	return responseWebSearchCallItem(call, includeSources)
}

func responseFunctionCallItem(responseID string, index int, call types.ToolCall) map[string]any {
	id := call.ID
	if id == "" {
		id = fmt.Sprintf("fc_%s_%d", strings.TrimPrefix(responseID, "resp_"), index)
	}
	callID := call.CallID
	if callID == "" {
		callID = id
	}
	return map[string]any{
		"id":        id,
		"type":      "function_call",
		"status":    "completed",
		"call_id":   callID,
		"name":      call.Name,
		"arguments": call.Arguments,
	}
}

func responseParallelToolCalls(meta *types.ResponseRequestMeta) bool {
	if meta != nil && meta.ParallelToolCalls != nil {
		return *meta.ParallelToolCalls
	}
	return true
}

func responseToolChoice(meta *types.ResponseRequestMeta) any {
	if meta != nil && meta.ToolChoice != nil {
		return meta.ToolChoice
	}
	return "auto"
}

func responseTools(meta *types.ResponseRequestMeta) []any {
	if meta == nil || len(meta.Tools) == 0 {
		return []any{}
	}
	return meta.Tools
}

func ResponsesOutputForUsage(result StreamResult) string {
	if len(result.ToolCalls) == 0 {
		return result.Text
	}
	var b strings.Builder
	if result.Text != "" {
		b.WriteString(result.Text)
	}
	for _, call := range result.ToolCalls {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(call.Name)
		b.WriteByte(' ')
		b.WriteString(call.Arguments)
	}
	return b.String()
}

func orderedToolCalls(byIndex map[int]*types.ToolCall, order []int) []types.ToolCall {
	if len(byIndex) == 0 {
		return nil
	}
	out := make([]types.ToolCall, 0, len(byIndex))
	for _, index := range order {
		if call := byIndex[index]; call != nil {
			out = append(out, *call)
		}
	}
	return out
}

func orderedThinking(byIndex map[int]*ThinkingBlock, order []int) []ThinkingBlock {
	if len(byIndex) == 0 {
		return nil
	}
	out := make([]ThinkingBlock, 0, len(byIndex))
	for _, index := range order {
		if tb := byIndex[index]; tb != nil {
			out = append(out, *tb)
		}
	}
	return out
}

func writeResponseEvent(w io.Writer, eventName string, payload map[string]any) error {
	return writeResponseEventSeq(w, nil, eventName, payload)
}

func writeResponseEventSeq(w io.Writer, seq *int, eventName string, payload map[string]any) error {
	if seq != nil {
		(*seq)++
		payload["sequence_number"] = *seq
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\n", eventName); err != nil {
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

func estimateTextTokens(text string) int {
	if text == "" {
		return 1
	}
	tokens := len(text) / 4
	if tokens < 1 {
		return 1
	}
	return tokens
}

func stringValue(value any) string {
	out, _ := value.(string)
	return out
}

func responsesTextFormatType(textConfig map[string]any) string {
	if len(textConfig) == 0 {
		return ""
	}
	format, ok := textConfig["format"].(map[string]any)
	if !ok {
		return ""
	}
	return strings.TrimSpace(stringValue(format["type"]))
}

func normalizeJSONString(candidate string, formatType string) (string, bool) {
	if candidate == "" {
		return "", false
	}
	var decoded any
	decoder := json.NewDecoder(strings.NewReader(candidate))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return "", false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", false
	}
	if formatType == "json_object" {
		if _, ok := decoded.(map[string]any); !ok {
			return "", false
		}
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

func extractFirstJSONValue(text string, formatType string) (string, bool) {
	for i, ch := range text {
		if ch != '{' && ch != '[' {
			continue
		}
		decoder := json.NewDecoder(strings.NewReader(text[i:]))
		decoder.UseNumber()
		var decoded any
		if err := decoder.Decode(&decoded); err != nil {
			continue
		}
		if formatType == "json_object" {
			if _, ok := decoded.(map[string]any); !ok {
				continue
			}
		}
		encoded, err := json.Marshal(decoded)
		if err != nil {
			continue
		}
		return string(encoded), true
	}
	return "", false
}

func presentNonNull(value json.RawMessage) bool {
	if len(value) == 0 {
		return false
	}
	trimmed := strings.TrimSpace(string(value))
	return trimmed != "" && trimmed != "null" && trimmed != "[]" && trimmed != "{}"
}

func boolField(raw map[string]json.RawMessage, key string) bool {
	value, ok := raw[key]
	if !ok {
		return false
	}
	var out bool
	return json.Unmarshal(value, &out) == nil && out
}

func containsAny(value json.RawMessage) bool {
	if !presentNonNull(value) {
		return false
	}
	var items []any
	if err := json.Unmarshal(value, &items); err == nil {
		return len(items) > 0
	}
	var obj map[string]any
	if err := json.Unmarshal(value, &obj); err == nil {
		return len(obj) > 0
	}
	return true
}

func validateTextModalities(value json.RawMessage) error {
	var modalities []string
	if err := json.Unmarshal(value, &modalities); err != nil && presentNonNull(value) {
		return &AdapterError{Status: 400, Message: "modalities must be an array", Context: "modalities"}
	}
	for _, modality := range modalities {
		if modality != "text" {
			return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "modalities"}
		}
	}
	return nil
}

func validateTextConfig(value json.RawMessage) error {
	if !presentNonNull(value) {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal(value, &parsed); err != nil {
		return &AdapterError{Status: 400, Message: "text must be an object", Context: "text"}
	}
	_, err := chatResponseFormatFromResponsesText(parsed)
	return err
}

func validateReasoningConfig(value json.RawMessage) error {
	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal(value, &parsed); err != nil {
		return &AdapterError{Status: 400, Message: "reasoning must be an object", Context: "reasoning"}
	}
	return nil
}

func chatResponseFormatFromResponsesText(textConfig map[string]any) (map[string]any, error) {
	if len(textConfig) == 0 {
		return nil, nil
	}
	format, ok := textConfig["format"].(map[string]any)
	if !ok || len(format) == 0 {
		return nil, nil
	}
	formatType := strings.TrimSpace(stringValue(format["type"]))
	switch formatType {
	case "", "text":
		return nil, nil
	case "json_object":
		return map[string]any{"type": "json_object"}, nil
	case "json_schema":
		if nested, ok := format["json_schema"].(map[string]any); ok && len(nested) > 0 {
			return map[string]any{"type": "json_schema", "json_schema": nested}, nil
		}
		schema, ok := format["schema"].(map[string]any)
		if !ok || len(schema) == 0 {
			return nil, &AdapterError{Status: 400, Message: "json_schema format requires schema", Context: "text.format.schema"}
		}
		jsonSchema := map[string]any{"schema": schema}
		if name := stringValue(format["name"]); name != "" {
			jsonSchema["name"] = name
		} else {
			jsonSchema["name"] = "response"
		}
		if description := stringValue(format["description"]); description != "" {
			jsonSchema["description"] = description
		}
		if strict, ok := format["strict"].(bool); ok {
			jsonSchema["strict"] = strict
		}
		return map[string]any{"type": "json_schema", "json_schema": jsonSchema}, nil
	default:
		return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "text.format"}
	}
}

func validateResponsesTools(value json.RawMessage) error {
	if !presentNonNull(value) {
		return nil
	}
	var tools []any
	if err := json.Unmarshal(value, &tools); err != nil {
		return &AdapterError{Status: 400, Message: "tools must be an array", Context: "tools"}
	}
	_, err := ChatToolsFromResponsesTools(tools)
	return err
}

func validateResponsesInclude(value json.RawMessage) error {
	if !presentNonNull(value) {
		return nil
	}
	var includes []string
	if err := json.Unmarshal(value, &includes); err != nil {
		return &AdapterError{Status: 400, Message: "include must be an array of strings", Context: "include"}
	}
	for _, include := range includes {
		if include != "web_search_call.action.sources" {
			return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "include"}
		}
	}
	return nil
}

func validateResponsesMaxToolCalls(value, tools json.RawMessage) error {
	var maxCalls int
	if err := json.Unmarshal(value, &maxCalls); err != nil || maxCalls < 1 {
		return &AdapterError{Status: 400, Message: "max_tool_calls must be a positive integer", Context: "max_tool_calls"}
	}
	if maxCalls > 3 {
		return &AdapterError{Status: 400, Message: "max_tool_calls cannot exceed 3", Context: "max_tool_calls"}
	}
	var parsed []any
	if err := json.Unmarshal(tools, &parsed); err != nil || !containsWebSearchTool(parsed) {
		return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "max_tool_calls"}
	}
	return nil
}

func validateResponsesToolChoice(value json.RawMessage) error {
	if !presentNonNull(value) {
		return nil
	}
	var parsed any
	if err := json.Unmarshal(value, &parsed); err != nil {
		return &AdapterError{Status: 400, Message: "invalid tool_choice", Context: "tool_choice"}
	}
	_, err := ChatToolChoiceFromResponses(parsed)
	return err
}

func ChatToolsFromResponsesTools(tools []any) ([]any, error) {
	if len(tools) == 0 {
		return nil, nil
	}
	out := make([]any, 0, len(tools))
	for _, tool := range tools {
		normalized, err := chatToolFromResponsesTool(tool)
		if err != nil {
			return nil, err
		}
		out = append(out, normalized)
	}
	return out, nil
}

func ResponsesWebSearchConfig(tools []any, maxToolCalls *int, includes []string) (*types.ResponseWebSearchConfig, error) {
	var config *types.ResponseWebSearchConfig
	for _, tool := range tools {
		m, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		toolType := stringValue(m["type"])
		if toolType != "web_search" && toolType != "web_search_preview" {
			continue
		}
		if config != nil {
			return nil, &AdapterError{Status: 400, Message: "only one web_search tool is allowed", Context: "tools"}
		}
		parsed, err := parseResponsesWebSearchTool(m)
		if err != nil {
			return nil, err
		}
		config = parsed
	}
	if config == nil {
		return nil, nil
	}
	config.MaxCalls = 3
	if maxToolCalls != nil {
		if *maxToolCalls < 1 || *maxToolCalls > 3 {
			return nil, &AdapterError{Status: 400, Message: "max_tool_calls must be between 1 and 3", Context: "max_tool_calls"}
		}
		config.MaxCalls = *maxToolCalls
	}
	for _, include := range includes {
		if include == "web_search_call.action.sources" {
			config.IncludeSources = true
		}
	}
	return config, nil
}

func containsWebSearchTool(tools []any) bool {
	for _, tool := range tools {
		m, ok := tool.(map[string]any)
		if !ok {
			continue
		}
		switch stringValue(m["type"]) {
		case "web_search", "web_search_preview":
			return true
		}
	}
	return false
}

func parseResponsesWebSearchTool(tool map[string]any) (*types.ResponseWebSearchConfig, error) {
	toolType := stringValue(tool["type"])
	allowed := map[string]struct{}{
		"type": {}, "search_context_size": {}, "filters": {}, "user_location": {},
		"external_web_access": {}, "return_token_budget": {}, "search_content_types": {}, "image_settings": {},
	}
	for key, value := range tool {
		if _, ok := allowed[key]; !ok && value != nil {
			return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools." + key}
		}
	}
	config := &types.ResponseWebSearchConfig{ToolType: toolType, SearchContextSize: "medium"}
	if size := strings.TrimSpace(stringValue(tool["search_context_size"])); size != "" {
		switch size {
		case "low", "medium", "high":
			config.SearchContextSize = size
		default:
			return nil, &AdapterError{Status: 400, Message: "invalid web search context size", Context: "tools.search_context_size"}
		}
	}
	if external, present := tool["external_web_access"]; present && external != nil {
		allowed, ok := external.(bool)
		if !ok {
			return nil, &AdapterError{Status: 400, Message: "external_web_access must be a boolean", Context: "tools.external_web_access"}
		}
		if !allowed {
			return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools.external_web_access"}
		}
	}
	if rawBudget, present := tool["return_token_budget"]; present && rawBudget != nil {
		budget, ok := rawBudget.(string)
		if !ok {
			return nil, &AdapterError{Status: 400, Message: "return_token_budget must be a string", Context: "tools.return_token_budget"}
		}
		if strings.TrimSpace(budget) != "default" {
			return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools.return_token_budget"}
		}
	}
	if rawContentTypes, present := tool["search_content_types"]; present && rawContentTypes != nil {
		contentTypes, ok := anyStringSlice(rawContentTypes)
		if !ok {
			return nil, &AdapterError{Status: 400, Message: "search_content_types must be an array of strings", Context: "tools.search_content_types"}
		}
		for _, contentType := range contentTypes {
			if contentType != "text" {
				return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools.search_content_types"}
			}
		}
	}
	if tool["image_settings"] != nil {
		return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools.image_settings"}
	}
	if rawFilters, present := tool["filters"]; present && rawFilters != nil {
		filters, ok := rawFilters.(map[string]any)
		if !ok {
			return nil, &AdapterError{Status: 400, Message: "web search filters must be an object", Context: "tools.filters"}
		}
		if toolType == "web_search_preview" && len(filters) > 0 {
			return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools.filters"}
		}
		for key := range filters {
			if key != "allowed_domains" && key != "blocked_domains" {
				return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools.filters." + key}
			}
		}
		var err error
		config.AllowedDomains, err = validatedDomains(filters["allowed_domains"])
		if err != nil {
			return nil, err
		}
		config.BlockedDomains, err = validatedDomains(filters["blocked_domains"])
		if err != nil {
			return nil, err
		}
	}
	if rawLocation, present := tool["user_location"]; present && rawLocation != nil {
		location, ok := rawLocation.(map[string]any)
		if !ok {
			return nil, &AdapterError{Status: 400, Message: "web search user_location must be an object", Context: "tools.user_location"}
		}
		for key := range location {
			switch key {
			case "type", "country", "city", "region", "timezone":
			default:
				return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools.user_location." + key}
			}
		}
		if kind := strings.TrimSpace(stringValue(location["type"])); kind != "" && kind != "approximate" {
			return nil, &AdapterError{Status: 400, Message: "invalid web search user location", Context: "tools.user_location.type"}
		}
		config.UserCountry = strings.ToUpper(strings.TrimSpace(stringValue(location["country"])))
		if config.UserCountry != "" && len(config.UserCountry) != 2 {
			return nil, &AdapterError{Status: 400, Message: "country must be a two-letter ISO code", Context: "tools.user_location.country"}
		}
		config.UserCity = truncateString(stringValue(location["city"]), 256)
		config.UserRegion = truncateString(stringValue(location["region"]), 256)
		config.UserTimezone = truncateString(stringValue(location["timezone"]), 128)
	}
	return config, nil
}

func validatedDomains(value any) ([]string, error) {
	values, ok := anyStringSlice(value)
	if !ok && value != nil {
		return nil, &AdapterError{Status: 400, Message: "web search domains must be strings", Context: "tools.filters"}
	}
	if len(values) > 100 {
		return nil, &AdapterError{Status: 400, Message: "web search domain filter cannot exceed 100 entries", Context: "tools.filters"}
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		domain := strings.ToLower(strings.TrimSpace(value))
		if domain == "" || strings.Contains(domain, "://") || strings.ContainsAny(domain, "/?#") || len(domain) > 253 {
			return nil, &AdapterError{Status: 400, Message: "invalid web search domain", Context: "tools.filters"}
		}
		out = append(out, domain)
	}
	return out, nil
}

func anyStringSlice(value any) ([]string, bool) {
	switch values := value.(type) {
	case nil:
		return nil, true
	case []string:
		return append([]string(nil), values...), true
	case []any:
		out := make([]string, 0, len(values))
		for _, raw := range values {
			text, ok := raw.(string)
			if !ok {
				return nil, false
			}
			out = append(out, text)
		}
		return out, true
	default:
		return nil, false
	}
}

func truncateString(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func chatToolFromResponsesTool(tool any) (map[string]any, error) {
	m, ok := tool.(map[string]any)
	if !ok {
		return nil, &AdapterError{Status: 400, Message: "tool must be an object", Context: "tools"}
	}
	switch stringValue(m["type"]) {
	case "web_search", "web_search_preview":
		if _, err := parseResponsesWebSearchTool(m); err != nil {
			return nil, err
		}
		return trustedRouterWebSearchFunctionTool(m), nil
	case "function":
	default:
		return nil, &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "tools"}
	}
	if fn, ok := m["function"].(map[string]any); ok {
		return normalizeChatFunctionTool(fn)
	}
	fn := map[string]any{}
	for _, key := range []string{"name", "description", "parameters", "strict"} {
		if value, ok := m[key]; ok {
			fn[key] = value
		}
	}
	return normalizeChatFunctionTool(fn)
}

func trustedRouterWebSearchFunctionTool(tool map[string]any) map[string]any {
	description := "Search the live web when current or sourced information is needed. Use a concise standalone search query."
	if location, ok := tool["user_location"].(map[string]any); ok {
		parts := []string{}
		for _, key := range []string{"city", "region", "country", "timezone"} {
			if value := strings.TrimSpace(stringValue(location[key])); value != "" {
				parts = append(parts, value)
			}
		}
		if len(parts) > 0 {
			description += " Approximate user location: " + strings.Join(parts, ", ") + "."
		}
	}
	return map[string]any{
		"type": "function",
		"function": map[string]any{
			"name":        TrustedRouterWebSearchFunction,
			"description": description,
			"strict":      true,
			"parameters": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"query": map[string]any{"type": "string", "description": "A standalone web search query."},
				},
				"required": []string{"query"},
			},
		},
	}
}

func normalizeChatFunctionTool(fn map[string]any) (map[string]any, error) {
	name := strings.TrimSpace(stringValue(fn["name"]))
	if name == "" {
		return nil, &AdapterError{Status: 400, Message: "function tool name is required", Context: "tools.function.name"}
	}
	if name == TrustedRouterWebSearchFunction {
		return nil, &AdapterError{Status: 501, Message: "reserved function name", Context: "tools.function.name"}
	}
	normalized := map[string]any{"name": name}
	if description := stringValue(fn["description"]); description != "" {
		normalized["description"] = description
	}
	if parameters, ok := fn["parameters"].(map[string]any); ok && len(parameters) > 0 {
		normalized["parameters"] = parameters
	} else {
		normalized["parameters"] = map[string]any{"type": "object", "properties": map[string]any{}}
	}
	if strict, ok := fn["strict"].(bool); ok {
		normalized["strict"] = strict
	}
	return map[string]any{"type": "function", "function": normalized}, nil
}

func ChatToolChoiceFromResponses(choice any) (any, error) {
	switch value := choice.(type) {
	case nil:
		return nil, nil
	case string:
		switch value {
		case "", "auto", "none", "required":
			return value, nil
		default:
			return nil, &AdapterError{Status: 400, Message: "invalid tool_choice", Context: "tool_choice"}
		}
	case map[string]any:
		choiceType := stringValue(value["type"])
		if choiceType == "web_search" || choiceType == "web_search_preview" {
			return map[string]any{
				"type":     "function",
				"function": map[string]any{"name": TrustedRouterWebSearchFunction},
			}, nil
		}
		if choiceType != "function" {
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
		return map[string]any{
			"type":     "function",
			"function": map[string]any{"name": name},
		}, nil
	default:
		return nil, &AdapterError{Status: 400, Message: "invalid tool_choice", Context: "tool_choice"}
	}
}

func responseTextConfig(textConfig map[string]any) map[string]any {
	if len(textConfig) == 0 {
		return map[string]any{"format": map[string]any{"type": "text"}}
	}
	if _, ok := textConfig["format"]; ok {
		return textConfig
	}
	return map[string]any{"format": map[string]any{"type": "text"}}
}

func validateTruncation(value json.RawMessage) error {
	if !presentNonNull(value) {
		return nil
	}
	var truncation string
	if err := json.Unmarshal(value, &truncation); err != nil {
		return &AdapterError{Status: 400, Message: "truncation must be a string", Context: "truncation"}
	}
	if truncation == "" || truncation == "disabled" {
		return nil
	}
	return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "truncation"}
}

func validateResponsesInput(raw json.RawMessage) error {
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	return validateResponsesInputValue(parsed)
}

func validateResponsesInputValue(value any) error {
	switch v := value.(type) {
	case map[string]any:
		t := stringValue(v["type"])
		switch {
		case strings.Contains(t, "file"):
			return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "file"}
		case strings.Contains(t, "audio"):
			return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "audio"}
		case strings.Contains(t, "video"):
			return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "video"}
		}
		for _, child := range v {
			if err := validateResponsesInputValue(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := validateResponsesInputValue(child); err != nil {
				return err
			}
		}
	}
	return nil
}
