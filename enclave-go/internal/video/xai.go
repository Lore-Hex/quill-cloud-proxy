package video

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const defaultXAIVideoBaseURL = "https://api.x.ai/v1"

type XAIClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewXAIClient(apiKey string, httpc *http.Client) *XAIClient {
	return NewXAIClientAt(apiKey, defaultXAIVideoBaseURL, httpc)
}

func NewXAIClientAt(apiKey, baseURL string, httpc *http.Client) *XAIClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &XAIClient{apiKey: strings.TrimSpace(apiKey), baseURL: strings.TrimRight(baseURL, "/"), httpc: httpc}
}

func (c *XAIClient) ID() string    { return "grok" }
func (c *XAIClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *XAIClient) Supports(request *ResolvedRequest) bool {
	if request == nil || request.Model.ID != "x-ai/grok-imagine-video" {
		return false
	}
	if request.LastFrame != "" || request.AudioReference != "" || request.VideoReference != "" {
		return false
	}
	if len(request.ReferenceImages) > 7 {
		return false
	}
	return len(request.ReferenceImages) == 0 || (request.FirstFrame == "" && request.DurationSeconds <= 10)
}

func (c *XAIClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("xai video provider does not support this request")
	}
	rate := 50_000
	if strings.EqualFold(request.Resolution, "720p") {
		rate = 70_000
	}
	imageCount := len(request.ReferenceImages)
	if request.FirstFrame != "" {
		imageCount++
	}
	return staticCustomerQuote(rate, request.DurationSeconds, imageCount*2_000)
}

func (c *XAIClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("xai video provider does not support this request")
	}
	payload := map[string]any{
		"model":        "grok-imagine-video",
		"prompt":       request.Prompt,
		"duration":     request.DurationSeconds,
		"aspect_ratio": request.AspectRatio,
		"resolution":   strings.ToLower(request.Resolution),
	}
	if request.FirstFrame != "" {
		payload["image"] = map[string]any{"url": request.FirstFrame}
	}
	if len(request.ReferenceImages) > 0 {
		references := make([]map[string]any, 0, len(request.ReferenceImages))
		for _, rawURL := range request.ReferenceImages {
			references = append(references, map[string]any{"url": rawURL})
		}
		payload["reference_images"] = references
	}
	resp, err := c.request(ctx, http.MethodPost, "/videos/generations", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&body); err != nil || strings.TrimSpace(body.RequestID) == "" {
		return nil, fmt.Errorf("xai video queue: invalid response")
	}
	return &QueueResult{ProviderModel: "grok-imagine-video", QueueID: body.RequestID}, nil
}

func (c *XAIClient) Retrieve(ctx context.Context, _ string, queueID string) (*PollResult, error) {
	resp, err := c.request(ctx, http.MethodGet, "/videos/"+strings.TrimSpace(queueID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Status string `json:"status"`
		Video  struct {
			URL string `json:"url"`
		} `json:"video"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&body); err != nil {
		return nil, fmt.Errorf("xai video retrieve: invalid response")
	}
	status := strings.ToUpper(strings.TrimSpace(body.Status))
	switch status {
	case "PENDING", "PROCESSING", "RUNNING", "QUEUED":
		return &PollResult{State: PollProcessing, ProviderStatus: status}, nil
	case "DONE", "COMPLETED", "SUCCEEDED":
		if strings.TrimSpace(body.Video.URL) == "" {
			return nil, fmt.Errorf("xai video retrieve: missing video URL")
		}
		return &PollResult{State: PollCompleted, ProviderStatus: status, DownloadURL: body.Video.URL}, nil
	case "FAILED", "EXPIRED", "CANCELLED", "CANCELED":
		return &PollResult{State: PollFailed, ProviderStatus: status}, nil
	default:
		return nil, fmt.Errorf("xai video retrieve: unknown status")
	}
}

func (c *XAIClient) Download(ctx context.Context, rawURL string) (*PollResult, error) {
	return downloadVideo(ctx, c.httpc, rawURL, c.ID(), nil)
}

func (c *XAIClient) Complete(context.Context, string, string) error { return nil }

func (c *XAIClient) request(ctx context.Context, method, path string, payload map[string]any) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("xai video provider is not configured")
	}
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xai video request failed: %w", err)
	}
	return resp, nil
}
