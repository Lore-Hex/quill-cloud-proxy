//go:build llm_multi

package llm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestVertexGeminiPrepaidUsesVertexGenerateContent(t *testing.T) {
	var capturedPath string
	var capturedQuery string
	var capturedBody map[string]any
	client := &vertexGeminiClient{
		auth: &gcpClient{
			projectID: "test-project",
			region:    "global",
			httpc: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				capturedPath = req.URL.Path
				capturedQuery = req.URL.RawQuery
				if got := req.Header.Get("Authorization"); got != "Bearer cached-token" {
					t.Fatalf("Authorization = %q", got)
				}
				if err := json.NewDecoder(req.Body).Decode(&capturedBody); err != nil {
					t.Fatalf("decode request body: %v", err)
				}
				body := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"PO\"}]}}]}\n\n" +
					"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"NG\"}]},\"finishReason\":\"STOP\"}]}\n\n"
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(body)),
					Header:     make(http.Header),
				}, nil
			})},
			token:    "cached-token",
			tokenExp: time.Now().Add(time.Hour),
		},
	}
	maxTokens := 64
	temp := 0.2
	req := &qtypes.OpenAIChatRequest{
		Model:       "google/gemini-2.5-flash",
		Messages:    []qtypes.OpenAIChatMessage{{Role: "user", Content: "Reply PONG"}},
		MaxTokens:   &maxTokens,
		Temperature: &temp,
	}
	body := &qtypes.AnthropicMessagesRequest{MaxTokens: maxTokens, Temperature: &temp}

	var out bytes.Buffer
	if err := client.InvokeStreaming(
		t.Context(),
		req,
		body,
		&out,
		InvokeOptions{Provider: "gemini", UpstreamModel: "google/gemini-2.5-flash"},
	); err != nil {
		t.Fatalf("InvokeStreaming: %v", err)
	}

	if capturedPath != "/v1/projects/test-project/locations/global/publishers/google/models/gemini-2.5-flash:streamGenerateContent" {
		t.Fatalf("path = %q", capturedPath)
	}
	if capturedQuery != "alt=sse" {
		t.Fatalf("query = %q", capturedQuery)
	}
	if !strings.Contains(out.String(), "PO") || !strings.Contains(out.String(), "NG") || !strings.Contains(out.String(), "message_stop") {
		t.Fatalf("bad anthropic output: %s", out.String())
	}
	config := capturedBody["generationConfig"].(map[string]any)
	if int(config["maxOutputTokens"].(float64)) != maxTokens {
		t.Fatalf("maxOutputTokens = %#v", config["maxOutputTokens"])
	}
	thinking := config["thinkingConfig"].(map[string]any)
	if int(thinking["thinkingBudget"].(float64)) != 0 {
		t.Fatalf("thinkingBudget = %#v", thinking["thinkingBudget"])
	}
	contents := capturedBody["contents"].([]any)
	parts := contents[0].(map[string]any)["parts"].([]any)
	if parts[0].(map[string]any)["text"] != "Reply PONG" {
		t.Fatalf("parts = %#v", parts)
	}
}

func TestVertexGeminiUsesMinimalThinkingForFlashTextModels(t *testing.T) {
	if got := vertexGeminiThinkingConfig("gemini-2.5-flash"); got["thinkingBudget"] != 0 {
		t.Fatalf("gemini-2.5-flash thinkingConfig = %#v", got)
	}
	if got := vertexGeminiThinkingConfig("gemini-3-flash-preview"); got["thinkingLevel"] != "minimal" {
		t.Fatalf("gemini-3-flash-preview thinkingConfig = %#v", got)
	}
	if got := vertexGeminiThinkingConfig("gemini-3.5-flash"); got["thinkingLevel"] != "minimal" {
		t.Fatalf("gemini-3.5-flash thinkingConfig = %#v", got)
	}
	if got := vertexGeminiThinkingConfig("gemini-3.1-pro-preview"); got != nil {
		t.Fatalf("gemini pro should not change thinking by default: %#v", got)
	}
	if got := vertexGeminiThinkingConfig("gemini-3.1-flash-image"); got != nil {
		t.Fatalf("image models should not change thinking: %#v", got)
	}
}

func TestVertexGeminiImageInputAndOutputStayInsideEnclave(t *testing.T) {
	imageURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(testPNG(t))
	var capturedBody map[string]any
	client := &vertexGeminiClient{
		auth: &gcpClient{
			projectID: "test-project",
			region:    "global",
			httpc: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if err := json.NewDecoder(req.Body).Decode(&capturedBody); err != nil {
					t.Fatalf("decode request body: %v", err)
				}
				body := "data: {\"candidates\":[{\"content\":{\"parts\":[" +
					"{\"text\":\"hidden thought\",\"thought\":true}," +
					"{\"text\":\"Here:\"}," +
					"{\"inlineData\":{\"mimeType\":\"image/png\",\"data\":\"UE5H\"}}" +
					"]},\"finishReason\":\"STOP\"}]}\n\n"
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(body)),
					Header:     make(http.Header),
				}, nil
			})},
			token:    "cached-token",
			tokenExp: time.Now().Add(time.Hour),
		},
	}
	req := &qtypes.OpenAIChatRequest{
		Model: "google/gemini-2.5-flash-image",
		Messages: []qtypes.OpenAIChatMessage{{
			Role: "user",
			Content: []qtypes.ChatContentPart{
				{Type: "image_url", ImageURL: &qtypes.ChatImageURL{URL: imageURL, Detail: "low"}},
				{Type: "text", Text: "make a small icon"},
			},
		}},
	}
	body := &qtypes.AnthropicMessagesRequest{MaxTokens: 4096}

	var out bytes.Buffer
	if err := client.InvokeStreaming(
		t.Context(),
		req,
		body,
		&out,
		InvokeOptions{Provider: "gemini", UpstreamModel: "google/gemini-2.5-flash-image"},
	); err != nil {
		t.Fatalf("InvokeStreaming: %v", err)
	}

	config := capturedBody["generationConfig"].(map[string]any)
	modalities := config["responseModalities"].([]any)
	if modalities[0] != "TEXT" || modalities[1] != "IMAGE" {
		t.Fatalf("responseModalities = %#v", modalities)
	}
	contents := capturedBody["contents"].([]any)
	parts := contents[0].(map[string]any)["parts"].([]any)
	if _, ok := parts[0].(map[string]any)["inlineData"]; !ok {
		t.Fatalf("first part missing inlineData: %#v", parts[0])
	}
	if strings.Contains(string(mustJSON(t, capturedBody)), "image_url") ||
		strings.Contains(string(mustJSON(t, capturedBody)), "data:image") {
		t.Fatalf("raw OpenAI image URL leaked upstream: %#v", capturedBody)
	}
	got := out.String()
	if strings.Contains(got, "hidden thought") {
		t.Fatalf("thought text leaked: %s", got)
	}
	if !strings.Contains(got, "Here:") || !strings.Contains(got, "data:image/png;base64,UE5H") {
		t.Fatalf("image output missing from stream: %s", got)
	}
}

func TestVertexGeminiResponseFormatBecomesResponseSchema(t *testing.T) {
	config := map[string]any{}
	applyVertexGeminiResponseFormat(config, map[string]any{
		"type": "json_schema",
		"json_schema": map[string]any{
			"schema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"title": map[string]any{
						"type":     "string",
						"format":   "uuid",
						"examples": []any{"x"},
					},
				},
				"required": []any{"title"},
			},
		},
	})

	if config["responseMimeType"] != "application/json" {
		t.Fatalf("responseMimeType = %#v", config["responseMimeType"])
	}
	schema := config["responseSchema"].(map[string]any)
	if _, ok := schema["additionalProperties"]; ok {
		t.Fatalf("additionalProperties was not stripped: %#v", schema)
	}
	title := schema["properties"].(map[string]any)["title"].(map[string]any)
	if title["type"] != "string" {
		t.Fatalf("title schema = %#v", title)
	}
	if _, ok := title["format"]; ok {
		t.Fatalf("format was not stripped: %#v", title)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}
