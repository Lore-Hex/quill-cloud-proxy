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
	if value, ok := raw["reasoning"]; ok && presentNonNull(value) {
		return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "reasoning"}
	}
	if value, ok := raw["include"]; ok && containsAny(value) {
		return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "include"}
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
	if value, ok := raw["max_tool_calls"]; ok && presentNonNull(value) {
		return &AdapterError{Status: 501, Message: "not_supported_in_alpha", Context: "max_tool_calls"}
	}
	if value, ok := raw["tools"]; ok {
		if err := validateResponsesTools(value); err != nil {
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
		Provider:       req.Provider,
		Metadata:       req.Metadata,
		Trace:          req.Trace,
		User:           req.User,
		SessionID:      req.SessionID,
		ResponseFormat: responseFormat,
		Tools:          tools,
		ToolChoice:     toolChoice,
		ParallelTools:  req.ParallelToolCalls,
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
			ToolChoice:           toolChoice,
			Tools:                tools,
			TopLogprobs:          req.TopLogprobs,
			Truncation:           req.Truncation,
			MaxOutputTokens:      req.MaxOutputTokens,
			MaxToolCalls:         req.MaxToolCalls,
			PromptCacheRetention: req.PromptCacheRetention,
			Reasoning:            req.Reasoning,
			Store:                false,
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
			if message := getMap(dataJSON, "message"); message != nil {
				mergeUsage(&usage, getMap(message, "usage"))
			}
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
				captured.WriteString(getString(delta, "text"))
			} else if delta != nil && getString(delta, "type") == "input_json_delta" {
				index := getInt(dataJSON, "index")
				call := toolCallsByIndex[index]
				if call != nil {
					call.Arguments += getString(delta, "partial_json")
				}
			} else if delta != nil && getString(delta, "type") == "thinking_delta" {
				index := getInt(dataJSON, "index")
				if tb := thinkingByIndex[index]; tb != nil {
					tb.Text += getString(delta, "thinking")
				}
			} else if delta != nil && getString(delta, "type") == "signature_delta" {
				index := getInt(dataJSON, "index")
				if tb := thinkingByIndex[index]; tb != nil {
					tb.Signature += getString(delta, "signature")
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
	cachedTokens, reasoningTokens := 0, 0
	if usage != nil {
		cachedTokens = usage.CacheReadInputTokens
		reasoningTokens = usage.ReasoningTokens
	}
	payload := responsesObject(responseID, model, text, toolCalls, inputTokens, outputTokens, cachedTokens, reasoningTokens, created, "completed", textConfig, meta)
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
	toolCallsByIndex := map[int]*types.ToolCall{}
	var toolOrder []int
	toolOutputIndexes := map[int]int{}
	toolDone := map[int]bool{}
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
			if block == nil || getString(block, "type") != "tool_use" {
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
			if !messageStarted && len(toolCalls) == 0 {
				if err := startMessage(); err != nil {
					return StreamResult{}, err
				}
			}
			return finishResponsesStream(w, &seq, responseID, messageID, model, captured.String(), toolCalls, inputTokens, created, finishReason, textConfig, meta, messageStarted, messageOutputIndex)
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return StreamResult{}, err
	}
	toolCalls := orderedToolCalls(toolCallsByIndex, toolOrder)
	if !messageStarted && len(toolCalls) == 0 {
		if err := startMessage(); err != nil {
			return StreamResult{}, err
		}
	}
	return finishResponsesStream(w, &seq, responseID, messageID, model, captured.String(), toolCalls, inputTokens, created, finishReason, textConfig, meta, messageStarted, messageOutputIndex)
}

func finishResponsesStream(
	w io.Writer,
	seq *int,
	responseID string,
	messageID string,
	model string,
	text string,
	toolCalls []types.ToolCall,
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
	return StreamResult{Text: text, FinishReason: finishReason, ToolCalls: toolCalls}, err
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
		if text != "" || len(toolCalls) == 0 {
			output = append(output, map[string]any{
				"id":     messageID,
				"type":   "message",
				"status": "completed",
				"role":   "assistant",
				"content": []map[string]any{{
					"type":        "output_text",
					"text":        text,
					"annotations": []any{},
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
	return map[string]any{
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

func chatToolFromResponsesTool(tool any) (map[string]any, error) {
	m, ok := tool.(map[string]any)
	if !ok {
		return nil, &AdapterError{Status: 400, Message: "tool must be an object", Context: "tools"}
	}
	if stringValue(m["type"]) != "function" {
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

func normalizeChatFunctionTool(fn map[string]any) (map[string]any, error) {
	name := strings.TrimSpace(stringValue(fn["name"]))
	if name == "" {
		return nil, &AdapterError{Status: 400, Message: "function tool name is required", Context: "tools.function.name"}
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
