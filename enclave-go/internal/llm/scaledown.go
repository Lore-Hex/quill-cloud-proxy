package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

var scaleDownPaths = map[string]string{
	"compress": "/compress/raw/", "summarize": "/summarization/abstractive",
	"extract": "/extract", "classify": "/classify",
}

// InputOnlyModel identifies native task contracts whose zero output count is
// authoritative. Callers must pass the selected route model, not user metadata.
func InputOnlyModel(model string) bool {
	if !strings.HasPrefix(model, "scaledown/") {
		return false
	}
	_, ok := scaleDownPaths[strings.TrimPrefix(model, "scaledown/")]
	return ok
}

func scaleDownPayload(req *qtypes.OpenAIChatRequest, operation string) ([]byte, error) {
	if req == nil || len(req.Tools) != 0 || req.ToolChoice != nil || len(req.ResponseFormat) != 0 {
		return nil, fmt.Errorf("llm/scaledown: send task configuration as JSON in one user message; tools and response_format are unsupported")
	}
	if _, ok := scaleDownPaths[operation]; !ok {
		return nil, fmt.Errorf("llm/scaledown: unknown task")
	}
	var input string
	var instructions []string
	users := 0
	for _, message := range req.Messages {
		content, ok := message.Content.(string)
		if !ok {
			return nil, fmt.Errorf("llm/scaledown: only text content is supported")
		}
		switch message.Role {
		case "system", "developer":
			instructions = append(instructions, content)
		case "user":
			users++
			input = content
		default:
			return nil, fmt.Errorf("llm/scaledown: send one task, not a chat history")
		}
	}
	if users != 1 || strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("llm/scaledown: exactly one nonempty user message is required")
	}
	payload := map[string]json.RawMessage{}
	if operation == "summarize" && !strings.HasPrefix(strings.TrimSpace(input), "{") {
		payload["text"], _ = json.Marshal(input)
	} else if err := json.Unmarshal([]byte(input), &payload); err != nil || payload == nil {
		return nil, fmt.Errorf("llm/scaledown: user message must contain a JSON task object")
	}
	allowed := map[string]bool{"text": true}
	switch operation {
	case "compress":
		allowed = map[string]bool{"context": true, "prompt": true, "scaledown": true}
	case "summarize":
		allowed["instructions"], allowed["max_tokens"] = true, true
	case "extract":
		allowed["entities"], allowed["threshold"], allowed["top_n"] = true, true, true
	case "classify":
		allowed["labels"], allowed["system_prompt"] = true, true
	}
	for field := range payload {
		if !allowed[field] {
			return nil, fmt.Errorf("llm/scaledown: unsupported task field")
		}
	}
	textField := "text"
	if operation == "compress" {
		textField = "context"
	}
	var source string
	if json.Unmarshal(payload[textField], &source) != nil || strings.TrimSpace(source) == "" {
		return nil, fmt.Errorf("llm/scaledown: task source text is required")
	}
	if operation == "compress" {
		var prompt string
		if json.Unmarshal(payload["prompt"], &prompt) != nil || strings.TrimSpace(prompt) == "" {
			return nil, fmt.Errorf("llm/scaledown: compression prompt is required")
		}
	}
	if operation == "extract" {
		var entities map[string]json.RawMessage
		if json.Unmarshal(payload["entities"], &entities) != nil || len(entities) == 0 {
			return nil, fmt.Errorf("llm/scaledown: nonempty entities object is required")
		}
	}
	if operation == "classify" {
		var labels []struct {
			Name   string `json:"name"`
			Rubric string `json:"rubric"`
		}
		if json.Unmarshal(payload["labels"], &labels) != nil || len(labels) < 2 || len(labels) > 26 {
			return nil, fmt.Errorf("llm/scaledown: provide 2 to 26 labels with name and rubric")
		}
		seen := map[string]bool{}
		for _, label := range labels {
			if strings.TrimSpace(label.Name) == "" || strings.TrimSpace(label.Rubric) == "" || seen[label.Name] {
				return nil, fmt.Errorf("llm/scaledown: labels need unique names and nonempty rubrics")
			}
			seen[label.Name] = true
		}
	}
	if len(instructions) > 0 {
		field := "instructions"
		switch operation {
		case "classify":
			field = "system_prompt"
		case "compress":
			field = "context"
		case "extract":
			return nil, fmt.Errorf("llm/scaledown: put extraction instructions in entity descriptions")
		}
		var existing string
		if raw, exists := payload[field]; exists && json.Unmarshal(raw, &existing) != nil {
			return nil, fmt.Errorf("llm/scaledown: instructions must be text")
		}
		payload[field], _ = json.Marshal(strings.Join(append(instructions, existing), "\n\n"))
	}
	if operation == "summarize" {
		limit := 4096
		if raw, ok := payload["max_tokens"]; ok {
			if json.Unmarshal(raw, &limit) != nil || limit < 1 || limit > 20048 {
				return nil, fmt.Errorf("llm/scaledown: max_tokens must be between 1 and 20048")
			}
		}
		for _, requested := range []*int{req.MaxTokens, req.MaxCompletionTokens, req.MaxOutputTokens} {
			if requested != nil && *requested < limit {
				limit = *requested
			}
		}
		if limit < 1 {
			return nil, fmt.Errorf("llm/scaledown: max_tokens must be positive")
		}
		payload["max_tokens"], _ = json.Marshal(limit)
	}
	return json.Marshal(payload)
}

func (c *openAICompatibleClient) invokeScaleDown(ctx context.Context, req *qtypes.OpenAIChatRequest, out io.Writer, option InvokeOptions) error {
	if option.ProviderAPIKey != "" || strings.EqualFold(option.UsageType, "byok") {
		return fmt.Errorf("llm/scaledown: only TrustedRouter credits are supported")
	}
	operation := option.UpstreamModel
	if operation == "" && req != nil {
		operation = strings.TrimPrefix(req.Model, "scaledown/")
	}
	payload, err := scaleDownPayload(req, operation)
	if err != nil {
		return &upstreamHTTPError{status: http.StatusBadRequest, body: err.Error()}
	}
	if c.apiKey == "" {
		return fmt.Errorf("llm/scaledown: missing api key")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+scaleDownPaths[operation], bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("llm/scaledown: cannot construct request")
	}
	request.Header.Set("x-api-key", c.apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "TrustedRouter/1.0")
	httpc, err := c.resolveHTTPClient()
	if err != nil || httpc == nil {
		return fmt.Errorf("llm/scaledown: http client unavailable")
	}
	client := *httpc
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("llm/scaledown: request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// Upstream errors can echo input. Preserve status for shared failover,
		// but never include response content or credentials in logged errors.
		return &upstreamHTTPError{status: response.StatusCode, body: "ScaleDown task request failed"}
	}
	const maxResponseBytes = 8 << 20
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return fmt.Errorf("llm/scaledown: response unreadable or too large")
	}
	var result struct {
		InputTokens *int               `json:"input_tokens"`
		Successful  *bool              `json:"successful"`
		Summary     *string            `json:"summary"`
		Entities    *[]json.RawMessage `json:"entities"`
		TopLabel    *string            `json:"top_label"`
		Results     json.RawMessage    `json:"results"`
	}
	if json.Unmarshal(raw, &result) != nil || result.InputTokens == nil || *result.InputTokens <= 0 || *result.InputTokens > 1<<31 {
		return fmt.Errorf("llm/scaledown: invalid or missing provider input token usage")
	}
	if operation == "compress" {
		var compressed struct {
			Success          bool   `json:"success"`
			CompressedPrompt string `json:"compressed_prompt"`
		}
		if json.Unmarshal(result.Results, &compressed) != nil || result.Successful == nil || !*result.Successful || !compressed.Success || strings.TrimSpace(compressed.CompressedPrompt) == "" {
			return fmt.Errorf("llm/scaledown: compression did not return a successful result")
		}
	}
	if (operation == "summarize" && (result.Summary == nil || strings.TrimSpace(*result.Summary) == "")) ||
		(operation == "extract" && result.Entities == nil) ||
		(operation == "classify" && (result.TopLabel == nil || *result.TopLabel == "")) {
		return fmt.Errorf("llm/scaledown: task did not return a successful result")
	}
	if err := writeAnthropicTextDelta(out, string(raw)); err != nil {
		return err
	}
	// Input-only metering is intentional, including summarization. These are
	// upstream-reported billable tokens, not a local estimate of the JSON output.
	return writeAnthropicStop(out, "end_turn", &openAIStreamUsage{PromptTokens: *result.InputTokens, TotalTokens: *result.InputTokens}, nil, nil)
}
