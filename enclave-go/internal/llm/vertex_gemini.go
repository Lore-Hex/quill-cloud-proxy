//go:build llm_multi

package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

// vertexGeminiClient serves TrustedRouter prepaid Gemini traffic through
// Vertex AI, so usage bills to normal GCP billing/credits instead of the
// separate AI Studio Gemini API prepay balance. BYOK Gemini requests are still
// intercepted by invokeBYOKStreaming before this client runs.
type vertexGeminiClient struct {
	auth *gcpClient
}

func newVertexGemini(_ *qtypes.BootstrapData) *vertexGeminiClient {
	projectID := os.Getenv("QUILL_GCP_PROJECT_ID")
	region := os.Getenv("QUILL_GEMINI_VERTEX_REGION")
	if region == "" {
		region = "global"
	}
	return &vertexGeminiClient{
		auth: &gcpClient{
			projectID: projectID,
			region:    region,
			httpc:     defaultHTTPClient(),
		},
	}
}

func (c *vertexGeminiClient) InvokeStreaming(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	out io.Writer,
	options ...InvokeOptions,
) error {
	if handled, err := invokeBYOKStreaming(ctx, req, body, out, firstOptions(options)); handled {
		return err
	}
	token, err := c.auth.fetchToken(ctx)
	if err != nil {
		return err
	}
	option := firstOptions(options)
	modelID := directModelID("gemini", req.Model, option.UpstreamModel)
	payload, err := vertexGeminiPayload(ctx, req, body, modelID)
	if err != nil {
		return err
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("llm/vertex-gemini: marshal body: %w", err)
	}
	url := fmt.Sprintf(
		"https://%s/v1/projects/%s/locations/%s/publishers/google/models/%s:streamGenerateContent?alt=sse",
		c.auth.vertexHost(), c.auth.projectID, c.auth.region, modelID,
	)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("User-Agent", "TrustedRouter/1.0")

	resp, err := c.auth.httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/vertex-gemini: invoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("llm/vertex-gemini: read error body: %w", readErr)
		}
		return &upstreamHTTPError{status: resp.StatusCode, body: string(errBody)}
	}
	return translateGeminiStreamToAnthropic(resp.Body, out)
}

func vertexGeminiPayload(
	ctx context.Context,
	req *qtypes.OpenAIChatRequest,
	body *qtypes.AnthropicMessagesRequest,
	modelID string,
) (map[string]any, error) {
	contents := make([]map[string]any, 0, len(req.Messages))
	systemParts := make([]map[string]any, 0, 1)
	for _, message := range req.Messages {
		parts, err := vertexGeminiParts(ctx, message.Content)
		if err != nil {
			return nil, err
		}
		role := strings.TrimSpace(strings.ToLower(message.Role))
		switch role {
		case "system", "developer":
			systemParts = append(systemParts, parts...)
			continue
		case "assistant", "model":
			role = "model"
		default:
			role = "user"
		}
		contents = append(contents, map[string]any{"role": role, "parts": parts})
	}
	if len(contents) == 0 {
		contents = append(contents, map[string]any{"role": "user", "parts": []map[string]any{{"text": ""}}})
	}
	payload := map[string]any{"contents": contents}
	if len(systemParts) > 0 {
		payload["systemInstruction"] = map[string]any{"parts": systemParts}
	}

	generationConfig := map[string]any{}
	if body != nil && body.MaxTokens > 0 {
		generationConfig["maxOutputTokens"] = body.MaxTokens
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		generationConfig["maxOutputTokens"] = *req.MaxTokens
	}
	if req.Temperature != nil {
		generationConfig["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		generationConfig["topP"] = *req.TopP
	}
	if vertexGeminiImageModel(modelID) {
		generationConfig["responseModalities"] = []string{"TEXT", "IMAGE"}
		generationConfig["candidateCount"] = 1
	}
	if thinkingConfig := vertexGeminiThinkingConfig(modelID, req); thinkingConfig != nil {
		generationConfig["thinkingConfig"] = thinkingConfig
	}
	applyVertexGeminiResponseFormat(generationConfig, req.ResponseFormat)
	if len(generationConfig) > 0 {
		payload["generationConfig"] = generationConfig
	}
	return payload, nil
}

func vertexGeminiParts(ctx context.Context, content any) ([]map[string]any, error) {
	switch value := content.(type) {
	case nil:
		return []map[string]any{{"text": ""}}, nil
	case string:
		return []map[string]any{{"text": value}}, nil
	case []qtypes.ChatContentPart:
		return vertexGeminiTypedParts(ctx, value)
	case []any:
		parts := make([]qtypes.ChatContentPart, 0, len(value))
		for _, item := range value {
			part, err := chatPartFromAny(item)
			if err != nil {
				return nil, err
			}
			parts = append(parts, part)
		}
		return vertexGeminiTypedParts(ctx, parts)
	default:
		return []map[string]any{{"text": fmt.Sprint(value)}}, nil
	}
}

func vertexGeminiTypedParts(ctx context.Context, parts []qtypes.ChatContentPart) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(parts))
	for _, part := range parts {
		switch part.Type {
		case "", "text", "input_text":
			if part.Text != "" {
				out = append(out, map[string]any{"text": part.Text})
			}
		case "image_url", "input_image":
			if part.ImageURL == nil || strings.TrimSpace(part.ImageURL.URL) == "" {
				return nil, fmt.Errorf("llm/vertex-gemini: image_url is required")
			}
			inline, err := vertexGeminiInlineData(ctx, part.ImageURL.URL)
			if err != nil {
				return nil, err
			}
			out = append(out, map[string]any{"inlineData": inline})
		default:
			return nil, fmt.Errorf("llm/vertex-gemini: unsupported content part %q", part.Type)
		}
	}
	if len(out) == 0 {
		out = append(out, map[string]any{"text": ""})
	}
	return out, nil
}

func vertexGeminiInlineData(ctx context.Context, rawURL string) (map[string]any, error) {
	mediaType, data, err := loadImageBytes(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	normalizedType, normalizedData, err := normalizeImageBytes(mediaType, data)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"mimeType": normalizedType,
		"data":     base64.StdEncoding.EncodeToString(normalizedData),
	}, nil
}

func vertexGeminiImageModel(modelID string) bool {
	modelID = strings.ToLower(modelID)
	return strings.Contains(modelID, "image")
}

func vertexGeminiThinkingConfig(modelID string, req *qtypes.OpenAIChatRequest) map[string]any {
	modelID = strings.ToLower(modelID)
	if effort := vertexGeminiReasoningEffort(req); effort != "" && !vertexGeminiImageModel(modelID) {
		switch effort {
		case "none", "off", "disable", "disabled", "minimal", "low":
			if strings.HasPrefix(modelID, "gemini-2.5") {
				return map[string]any{"thinkingBudget": 0}
			}
			return map[string]any{"thinkingLevel": "low"}
		case "high":
			return map[string]any{"thinkingLevel": "high"}
		}
	}
	if !strings.Contains(modelID, "flash") || vertexGeminiImageModel(modelID) {
		return nil
	}
	if strings.HasPrefix(modelID, "gemini-2.5") {
		return map[string]any{"thinkingBudget": 0}
	}
	return map[string]any{"thinkingLevel": "minimal"}
}

func vertexGeminiReasoningEffort(req *qtypes.OpenAIChatRequest) string {
	if req == nil {
		return ""
	}
	if effort := strings.TrimSpace(strings.ToLower(req.ReasoningEffort)); effort != "" {
		return effort
	}
	reasoning, ok := req.Reasoning.(map[string]any)
	if !ok {
		return ""
	}
	effort, _ := reasoning["effort"].(string)
	return strings.TrimSpace(strings.ToLower(effort))
}

func applyVertexGeminiResponseFormat(config map[string]any, responseFormat map[string]any) {
	if len(responseFormat) == 0 {
		return
	}
	formatType, _ := responseFormat["type"].(string)
	switch formatType {
	case "json_object":
		config["responseMimeType"] = "application/json"
	case "json_schema":
		schemaBlock, _ := responseFormat["json_schema"].(map[string]any)
		schema, _ := schemaBlock["schema"].(map[string]any)
		if schema != nil {
			config["responseMimeType"] = "application/json"
			config["responseSchema"] = sanitizeGeminiSchema(schema)
		}
	}
}

func sanitizeGeminiSchema(schema map[string]any) map[string]any {
	allowed := map[string]struct{}{
		"type":             {},
		"properties":       {},
		"items":            {},
		"required":         {},
		"enum":             {},
		"description":      {},
		"nullable":         {},
		"minimum":          {},
		"maximum":          {},
		"minLength":        {},
		"maxLength":        {},
		"minItems":         {},
		"maxItems":         {},
		"propertyOrdering": {},
	}
	out := make(map[string]any, len(schema))
	for key, value := range schema {
		if _, ok := allowed[key]; !ok {
			continue
		}
		switch key {
		case "properties":
			props, ok := value.(map[string]any)
			if !ok {
				continue
			}
			clean := make(map[string]any, len(props))
			for name, rawProp := range props {
				if prop, ok := rawProp.(map[string]any); ok {
					clean[name] = sanitizeGeminiSchema(prop)
				}
			}
			out[key] = clean
		case "items":
			if item, ok := value.(map[string]any); ok {
				out[key] = sanitizeGeminiSchema(item)
			}
		default:
			out[key] = value
		}
	}
	return out
}

func translateGeminiStreamToAnthropic(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 64<<20)

	stopReason := "end_turn"
	var usage *openAIStreamUsage
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		delta, reason, chunkUsage, err := geminiChunkDelta(payload)
		if err != nil {
			continue
		}
		if chunkUsage != nil {
			usage = chunkUsage
		}
		if delta != "" {
			if err := writeAnthropicTextDelta(w, delta); err != nil {
				return err
			}
		}
		if reason != "" {
			stopReason = mapGeminiFinishReason(reason)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("llm/vertex-gemini-stream: scan: %w", err)
	}
	return writeAnthropicStop(w, stopReason, usage)
}

func geminiChunkDelta(payload string) (string, string, *openAIStreamUsage, error) {
	var chunk struct {
		Candidates []struct {
			Content struct {
				Parts []map[string]any `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		// usageMetadata rides the final chunk. candidatesTokenCount
		// EXCLUDES thoughts; Vertex bills thoughts as output, so the
		// relayed output count is candidates+thoughts.
		UsageMetadata *struct {
			PromptTokenCount        int `json:"promptTokenCount"`
			CandidatesTokenCount    int `json:"candidatesTokenCount"`
			ThoughtsTokenCount      int `json:"thoughtsTokenCount"`
			CachedContentTokenCount int `json:"cachedContentTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
		return "", "", nil, err
	}
	var usage *openAIStreamUsage
	if meta := chunk.UsageMetadata; meta != nil && (meta.PromptTokenCount > 0 || meta.CandidatesTokenCount > 0) {
		usage = &openAIStreamUsage{
			PromptTokens:     meta.PromptTokenCount,
			CompletionTokens: meta.CandidatesTokenCount + meta.ThoughtsTokenCount,
			TotalTokens:      meta.PromptTokenCount + meta.CandidatesTokenCount + meta.ThoughtsTokenCount,
		}
		if meta.ThoughtsTokenCount > 0 {
			usage.CompletionTokensDetails = &openAIStreamUsageDetails{ReasoningTokens: meta.ThoughtsTokenCount}
		}
		if meta.CachedContentTokenCount > 0 {
			usage.PromptTokensDetails = &openAIPromptTokenDetails{CachedTokens: meta.CachedContentTokenCount}
		}
	}
	if len(chunk.Candidates) == 0 {
		return "", "", usage, nil
	}
	var text strings.Builder
	for _, part := range chunk.Candidates[0].Content.Parts {
		if thought, _ := part["thought"].(bool); thought {
			continue
		}
		if value, _ := part["text"].(string); value != "" {
			text.WriteString(value)
		}
		if dataURL := geminiInlineDataURL(part); dataURL != "" {
			if text.Len() > 0 {
				text.WriteString("\n")
			}
			text.WriteString(dataURL)
		}
	}
	return text.String(), chunk.Candidates[0].FinishReason, usage, nil
}

func geminiInlineDataURL(part map[string]any) string {
	inline, ok := part["inlineData"].(map[string]any)
	if !ok {
		inline, ok = part["inline_data"].(map[string]any)
	}
	if !ok {
		return ""
	}
	mimeType, _ := inline["mimeType"].(string)
	if mimeType == "" {
		mimeType, _ = inline["mime_type"].(string)
	}
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	data, _ := inline["data"].(string)
	if data == "" {
		return ""
	}
	return "data:" + mimeType + ";base64," + data
}

func mapGeminiFinishReason(reason string) string {
	switch strings.ToUpper(strings.TrimSpace(reason)) {
	case "MAX_TOKENS":
		return "max_tokens"
	case "STOP":
		return "end_turn"
	default:
		return "end_turn"
	}
}
