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
	toolNameByID := map[string]string{}
	for _, message := range req.Messages {
		role := strings.TrimSpace(strings.ToLower(message.Role))
		switch role {
		case "system", "developer":
			parts, err := vertexGeminiParts(ctx, message.Content)
			if err != nil {
				return nil, err
			}
			systemParts = append(systemParts, parts...)
		case "tool", "function":
			// OpenAI tool result -> Gemini functionResponse part. Gemini needs
			// the function NAME; OpenAI tool messages only carry tool_call_id, so
			// correlate it from the assistant tool_calls seen earlier.
			cleanID, _ := geminiSplitToolID(message.ToolCallID)
			name := toolNameByID[cleanID]
			if name == "" {
				name = strings.TrimSpace(message.Name)
			}
			if name == "" {
				name = "tool"
			}
			frPart := map[string]any{
				"functionResponse": map[string]any{
					"name":     name,
					"response": map[string]any{"result": qtypes.ContentText(message.Content)},
				},
			}
			// Gemini requires the N functionResponses answering a parallel-call
			// turn (N functionCalls in one model content) to be GROUPED in ONE
			// user content — else "number of function response parts [must] equal
			// the number of function call parts" (400). Merge consecutive tool
			// results into the previous functionResponse content.
			if n := len(contents); n > 0 && isGeminiFunctionResponseContent(contents[n-1]) {
				contents[n-1]["parts"] = append(contents[n-1]["parts"].([]map[string]any), frPart)
			} else {
				contents = append(contents, map[string]any{
					"role":  "user",
					"parts": []map[string]any{frPart},
				})
			}
		case "assistant", "model":
			// Any text plus assistant tool_calls -> Gemini functionCall parts.
			parts := make([]map[string]any, 0, 1+len(message.ToolCalls))
			if text := qtypes.ContentText(message.Content); strings.TrimSpace(text) != "" {
				parts = append(parts, map[string]any{"text": text})
			}
			for _, call := range message.ToolCalls {
				cleanID, signature := geminiSplitToolID(call.ID)
				toolNameByID[cleanID] = call.Function.Name
				part := map[string]any{
					"functionCall": map[string]any{
						"name": call.Function.Name,
						"args": geminiToolArgs(call.Function.Arguments),
					},
				}
				// Gemini 3.x rejects a history functionCall with no thought_signature.
				// Echo the real one when we captured it (solo Gemini round-trip); else
				// attach a valid-base64 placeholder so cross-model histories (Fusion
				// panels replaying another model's tool calls) are accepted.
				if signature == "" {
					signature = geminiPlaceholderSignature
				}
				part["thoughtSignature"] = signature
				parts = append(parts, part)
			}
			if len(parts) == 0 {
				parts = append(parts, map[string]any{"text": ""})
			}
			contents = append(contents, map[string]any{"role": "model", "parts": parts})
		default:
			parts, err := vertexGeminiParts(ctx, message.Content)
			if err != nil {
				return nil, err
			}
			contents = append(contents, map[string]any{"role": "user", "parts": parts})
		}
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
	if stops := req.StopSequences(); len(stops) > 0 {
		generationConfig["stopSequences"] = stops
	} else if body != nil && len(body.StopSequences) > 0 {
		generationConfig["stopSequences"] = append([]string(nil), body.StopSequences...)
	}
	if req.FrequencyPenalty != nil {
		generationConfig["frequencyPenalty"] = *req.FrequencyPenalty
	}
	if req.PresencePenalty != nil {
		generationConfig["presencePenalty"] = *req.PresencePenalty
	}
	if req.Seed != nil {
		generationConfig["seed"] = *req.Seed
	}
	if body != nil && body.TopK != nil {
		generationConfig["topK"] = *body.TopK
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
	if toolDecls := geminiToolsFromChat(req.Tools); len(toolDecls) > 0 {
		payload["tools"] = []map[string]any{{"functionDeclarations": toolDecls}}
		if toolConfig := geminiToolConfig(req.ToolChoice); toolConfig != nil {
			payload["toolConfig"] = toolConfig
		}
	}
	return payload, nil
}

// geminiToolsFromChat converts OpenAI-style function tools into Gemini
// functionDeclarations. Non-function tool types are skipped.
func geminiToolsFromChat(tools []any) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, tool := range tools {
		m, ok := tool.(map[string]any)
		if !ok || stringValue(m["type"]) != "function" {
			continue
		}
		fn, ok := m["function"].(map[string]any)
		if !ok {
			continue
		}
		name := strings.TrimSpace(stringValue(fn["name"]))
		if name == "" {
			continue
		}
		decl := map[string]any{"name": name}
		if desc := stringValue(fn["description"]); desc != "" {
			decl["description"] = desc
		}
		if params, ok := fn["parameters"].(map[string]any); ok && len(params) > 0 {
			decl["parameters"] = sanitizeGeminiSchema(params)
		}
		out = append(out, decl)
	}
	return out
}

// geminiToolConfig maps an OpenAI tool_choice string to Gemini's
// functionCallingConfig mode. Returns nil for unrecognized / absent choices
// (Gemini defaults to AUTO).
func geminiToolConfig(toolChoice any) map[string]any {
	choice, ok := toolChoice.(string)
	if !ok {
		return nil
	}
	mode := ""
	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "none":
		mode = "NONE"
	case "required", "any":
		mode = "ANY"
	case "auto":
		mode = "AUTO"
	}
	if mode == "" {
		return nil
	}
	return map[string]any{"functionCallingConfig": map[string]any{"mode": mode}}
}

// geminiToolArgs parses an OpenAI tool_call arguments JSON string into the
// object Gemini's functionCall.args expects.
func geminiToolArgs(arguments string) map[string]any {
	arguments = strings.TrimSpace(arguments)
	if arguments == "" {
		return map[string]any{}
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(arguments), &parsed); err != nil || parsed == nil {
		return map[string]any{}
	}
	return parsed
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
	is25 := strings.HasPrefix(modelID, "gemini-2.5")
	// Explicit numeric thinking budget (OpenRouter-style `reasoning.max_tokens`),
	// exposing Gemini's native thinkingBudget so a caller can request full
	// reasoning instead of the cost-conscious default. -1 = dynamic (the model
	// thinks as much as it needs, up to its max); 0 = off; N = a token budget.
	// Gemini 2.5 takes a token budget; Gemini 3+ takes a level, so map there.
	if budget, ok := vertexGeminiThinkingBudget(req); ok && !vertexGeminiImageModel(modelID) {
		if is25 {
			return map[string]any{"thinkingBudget": budget}
		}
		if budget == 0 {
			return map[string]any{"thinkingLevel": "low"}
		}
		return map[string]any{"thinkingLevel": "high"}
	}
	if effort := vertexGeminiReasoningEffort(req); effort != "" && !vertexGeminiImageModel(modelID) {
		switch effort {
		case "none", "off", "disable", "disabled", "minimal", "low":
			if is25 {
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
	if is25 {
		return map[string]any{"thinkingBudget": 0}
	}
	return map[string]any{"thinkingLevel": "minimal"}
}

// vertexGeminiThinkingBudget reads an explicit thinking-token budget from the
// request's `reasoning` object: OpenRouter-style `reasoning.max_tokens`, or the
// aliases `thinking_budget` / `budget_tokens`. Returns (budget, true) when one
// is set. This is the path to Gemini's native thinkingBudget; -1 requests
// dynamic (full) thinking, which is what reproduces the labs' thinking-mode scores.
func vertexGeminiThinkingBudget(req *qtypes.OpenAIChatRequest) (int, bool) {
	if req == nil {
		return 0, false
	}
	reasoning, ok := req.Reasoning.(map[string]any)
	if !ok {
		return 0, false
	}
	for _, key := range []string{"max_tokens", "thinking_budget", "budget_tokens"} {
		if raw, present := reasoning[key]; present {
			if n, ok := vertexGeminiToInt(raw); ok {
				return n, true
			}
		}
	}
	return 0, false
}

func vertexGeminiToInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i), true
		}
	}
	return 0, false
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
	toolIndex := 1 // index 0 is reserved for the text content block
	sawTool := false
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		delta, calls, reason, chunkUsage, err := geminiChunkDelta(payload)
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
		for _, call := range calls {
			sawTool = true
			id := fmt.Sprintf("call_%d", toolIndex)
			if call.Signature != "" {
				// Carry the thought_signature back on the next turn via the id.
				id += geminiSignatureDelimiter + call.Signature
			}
			if err := writeAnthropicToolStart(w, toolIndex, id, call.Name); err != nil {
				return err
			}
			argsJSON, _ := json.Marshal(call.Args)
			if err := writeAnthropicToolDelta(w, toolIndex, string(argsJSON)); err != nil {
				return err
			}
			if err := writeAnthropicToolStop(w, toolIndex); err != nil {
				return err
			}
			toolIndex++
		}
		if reason != "" {
			stopReason = mapGeminiFinishReason(reason)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("llm/vertex-gemini-stream: scan: %w", err)
	}
	// Gemini reports finishReason STOP even when it emitted a functionCall;
	// surface tool_use so the client/agentic loop sees the tool calls.
	if sawTool {
		stopReason = "tool_use"
	}
	return writeAnthropicStop(w, stopReason, usage)
}

// geminiSignatureDelimiter stashes a Gemini-3 functionCall thought_signature
// inside the OpenAI tool_call id — the only field that survives the
// Gemini->Anthropic->OpenAI->(client)->Anthropic->Gemini round-trip. Gemini 3
// requires the signature echoed back on every functionCall in history (a 400
// otherwise), but OpenAI tool_calls have no field for it. ":" never appears in
// base64, so this delimiter cannot collide with a real signature.
const geminiSignatureDelimiter = "::gts::"

// geminiPlaceholderSignature is a valid-base64 sentinel attached to functionCall
// parts in history that carry NO real Gemini thought_signature. Gemini 3.x hard-
// rejects a functionCall in history with no thought_signature (400 "Function call
// is missing a thought_signature"), which broke the Fusion panel: it replays the
// caller's multi-turn tool history (run_shell calls synthesized by a DIFFERENT
// model / the fuser) to each Gemini panelist, so those calls never had a Gemini
// signature to echo. The field is TYPE_BYTES and Gemini validates only that it is
// syntactically base64 — it does NOT cryptographically verify the bytes on replay.
// Verified live against gemini-3.1-pro-preview and gemini-3.5-flash: no signature
// -> 400; non-base64 -> 400; ANY valid base64 ("skip", "AAAA") -> accepted and the
// model answers normally. Real signatures (solo Gemini path, encoded via
// geminiSignatureDelimiter in the tool id) always take precedence over this.
const geminiPlaceholderSignature = "c2tpcA==" // base64("skip")

func geminiSplitToolID(id string) (cleanID string, signature string) {
	if idx := strings.Index(id, geminiSignatureDelimiter); idx != -1 {
		return id[:idx], id[idx+len(geminiSignatureDelimiter):]
	}
	return id, ""
}

// isGeminiFunctionResponseContent reports whether a content is a user turn whose
// parts are all functionResponses (so the next tool result can be merged in).
func isGeminiFunctionResponseContent(content map[string]any) bool {
	if content["role"] != "user" {
		return false
	}
	parts, ok := content["parts"].([]map[string]any)
	if !ok || len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if _, has := part["functionResponse"]; !has {
			return false
		}
	}
	return true
}

type geminiFunctionCall struct {
	Name      string
	Args      map[string]any
	Signature string
}

func geminiChunkDelta(payload string) (string, []geminiFunctionCall, string, *openAIStreamUsage, error) {
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
		return "", nil, "", nil, err
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
		return "", nil, "", usage, nil
	}
	var text strings.Builder
	var calls []geminiFunctionCall
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
		if fc, ok := part["functionCall"].(map[string]any); ok {
			name := stringValue(fc["name"])
			args, _ := fc["args"].(map[string]any)
			if args == nil {
				args = map[string]any{}
			}
			calls = append(calls, geminiFunctionCall{
				Name:      name,
				Args:      args,
				Signature: stringValue(part["thoughtSignature"]),
			})
		}
	}
	return text.String(), calls, chunk.Candidates[0].FinishReason, usage, nil
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
