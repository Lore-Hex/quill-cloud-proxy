package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const clairicModel = "cloudflare/clairic"
const clairicUpstream = "@cf/cloudflare/clairic"

var clairicFieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$`)

func cloudflareGatewayHeaders(header http.Header) {
	// Use the funded gateway without retaining task content in logs or caches.
	header.Set("cf-aig-gateway-id", "default")
	header.Set("cf-aig-collect-log", "false")
	header.Set("cf-aig-collect-log-payload", "false")
	header.Set("cf-aig-skip-cache", "true")
}

type clairicTask struct {
	Model         string                     `json:"model"`
	State         string                     `json:"state,omitempty"`
	Fields        map[string]json.RawMessage `json:"fields"`
	Images        []json.RawMessage          `json:"images,omitempty"`
	ReferenceDate string                     `json:"reference_date,omitempty"`
	Options       json.RawMessage            `json:"options,omitempty"`
}

func clairicPayload(req *qtypes.OpenAIChatRequest) (*clairicTask, error) {
	invalid := func() (*clairicTask, error) {
		return nil, &upstreamHTTPError{status: 400, body: "Clairic requires one user message containing native task JSON with state and typed fields; no chat history, tools or response_format"}
	}
	if req == nil || len(req.Messages) != 1 || req.Messages[0].Role != "user" || len(req.Tools) != 0 || req.ToolChoice != nil || len(req.ResponseFormat) != 0 {
		return invalid()
	}
	content, err := textOnlyContent(req.Messages[0].Content)
	if err != nil {
		return nil, err
	}
	if len(content) > 16<<20 || decide.CheckNoDuplicateKeys([]byte(content)) != nil {
		return invalid()
	}
	var task clairicTask
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&task) != nil || len(task.Fields) == 0 || len(task.Images) > 4 || (strings.TrimSpace(task.State) == "" && len(task.Images) == 0) {
		return invalid()
	}
	if decoder.Decode(new(any)) != io.EOF {
		return invalid()
	}
	if task.Model != "" && task.Model != "clairic" && task.Model != clairicUpstream && task.Model != clairicModel {
		return invalid()
	}
	task.Model = "clairic"
	for name, raw := range task.Fields {
		var field struct {
			Type  string `json:"type"`
			Items string `json:"items"`
		}
		if !clairicFieldName.MatchString(name) || json.Unmarshal(raw, &field) != nil {
			return invalid()
		}
		switch field.Type {
		case "text", "number", "date", "time", "datetime", "duration", "estimate", "forecast":
		case "list":
			if field.Items != "text" && field.Items != "number" && field.Items != "date" {
				return invalid()
			}
		default:
			return invalid()
		}
	}
	// Never fetch caller URLs. Only the provider's documented embedded image
	// forms are forwarded; bound decoded sizes before allocating image bytes.
	total := 0
	for _, raw := range task.Images {
		var data, media string
		if json.Unmarshal(raw, &data) == nil {
			header, encoded, ok := strings.Cut(data, ",")
			if !ok || !strings.HasPrefix(strings.ToLower(header), "data:") || !strings.HasSuffix(header, ";base64") {
				return invalid()
			}
			media, data = header[5:len(header)-7], encoded
		} else {
			var image struct {
				ContentType string `json:"content_type"`
				Base64      string `json:"base64"`
			}
			if json.Unmarshal(raw, &image) != nil {
				return invalid()
			}
			media, data = image.ContentType, image.Base64
		}
		if (media != "image/png" && media != "image/jpeg" && media != "image/webp") || len(data) > base64.StdEncoding.EncodedLen(4<<20) {
			return invalid()
		}
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil || len(decoded) == 0 || len(decoded) > 4<<20 {
			return invalid()
		}
		total += len(decoded)
		if total > 8<<20 {
			return invalid()
		}
	}
	return &task, nil
}

func (c *openAICompatibleClient) invokeClairic(ctx context.Context, req *qtypes.OpenAIChatRequest, out io.Writer, option InvokeOptions) error {
	if option.ProviderAPIKey != "" || strings.EqualFold(option.UsageType, "byok") {
		return fmt.Errorf("llm/cloudflare: Clairic requires TrustedRouter credits")
	}
	task, err := clairicPayload(req)
	if err != nil {
		return err
	}
	if c.apiKey == "" || !strings.HasSuffix(c.baseURL, "/ai/v1") {
		return fmt.Errorf("llm/cloudflare: Clairic configuration unavailable")
	}
	raw, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("llm/cloudflare: invalid Clairic task")
	}
	url := strings.TrimSuffix(c.baseURL, "/v1") + "/run/" + clairicUpstream
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("llm/cloudflare: cannot construct Clairic request")
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "TrustedRouter/1.0")
	cloudflareGatewayHeaders(request.Header)
	httpc, err := c.resolveHTTPClient()
	if err != nil || httpc == nil {
		return fmt.Errorf("llm/cloudflare: HTTP client unavailable")
	}
	client := *httpc
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("llm/cloudflare: Clairic transport failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &upstreamHTTPError{status: response.StatusCode, body: "Clairic task failed"}
	}
	const maxResponse = 8 << 20
	raw, err = io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(raw) > maxResponse || decide.CheckNoDuplicateKeys(raw) != nil {
		return fmt.Errorf("llm/cloudflare: invalid Clairic response")
	}
	var envelope struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	if json.Unmarshal(raw, &envelope) != nil || !envelope.Success {
		return fmt.Errorf("llm/cloudflare: Clairic task unsuccessful")
	}
	var result struct {
		Model     string                     `json:"model"`
		Answers   map[string]json.RawMessage `json:"answers"`
		Truncated *bool                      `json:"truncated"`
		Usage     struct {
			Input  *int `json:"input_tokens"`
			Output *int `json:"output_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(envelope.Result, &result) != nil || (result.Model != "clairic" && result.Model != clairicUpstream) || result.Truncated == nil || result.Usage.Input == nil || *result.Usage.Input <= 0 || *result.Usage.Input > 1<<31 || result.Usage.Output == nil || *result.Usage.Output != 0 || len(result.Answers) != len(task.Fields) {
		return fmt.Errorf("llm/cloudflare: invalid Clairic result or token usage")
	}
	for name, field := range task.Fields {
		var spec struct {
			Type string `json:"type"`
		}
		var answer map[string]json.RawMessage
		_ = json.Unmarshal(field, &spec)
		if json.Unmarshal(result.Answers[name], &answer) != nil || answer == nil {
			return fmt.Errorf("llm/cloudflare: missing Clairic answer")
		}
		var kind string
		if json.Unmarshal(answer["type"], &kind) != nil || kind != spec.Type || answer["value"] == nil {
			return fmt.Errorf("llm/cloudflare: invalid Clairic answer")
		}
	}
	if err := writeAnthropicTextDelta(out, string(envelope.Result)); err != nil {
		return err
	}
	return writeAnthropicStop(out, "end_turn", &openAIStreamUsage{PromptTokens: *result.Usage.Input, TotalTokens: *result.Usage.Input}, nil, nil, nil)
}
