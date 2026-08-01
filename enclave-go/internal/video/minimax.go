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

const defaultMiniMaxVideoBaseURL = "https://api.minimax.io"

type MiniMaxClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewMiniMaxClient(apiKey string, httpc *http.Client) *MiniMaxClient {
	return NewMiniMaxClientAt(apiKey, defaultMiniMaxVideoBaseURL, httpc)
}

func NewMiniMaxClientAt(apiKey, baseURL string, httpc *http.Client) *MiniMaxClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &MiniMaxClient{apiKey: strings.TrimSpace(apiKey), baseURL: strings.TrimRight(baseURL, "/"), httpc: httpc}
}

func (c *MiniMaxClient) ID() string    { return "minimax" }
func (c *MiniMaxClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *MiniMaxClient) Supports(request *ResolvedRequest) bool {
	return request != nil && request.Model.ID == "minimax/hailuo-3"
}

func (c *MiniMaxClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("minimax video provider does not support this request")
	}
	imageCount := len(request.ReferenceImages)
	if request.FirstFrame != "" {
		imageCount++
	}
	if request.LastFrame != "" {
		imageCount++
	}
	extraImages := imageCount - 5
	if extraImages < 0 {
		extraImages = 0
	}
	// MiniMax H3 is $0.14/s at 2K. The first five reference images and
	// audio references are free; each additional image is $0.08.
	return staticCustomerQuote(140_000, request.DurationSeconds, extraImages*80_000)
}

func (c *MiniMaxClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("minimax video provider does not support this request")
	}
	content := []map[string]any{{"type": "text", "text": request.Prompt}}
	if request.FirstFrame != "" {
		content = append(content, miniMaxURLContent("image_url", "image_url", request.FirstFrame, "first_frame"))
	}
	if request.LastFrame != "" {
		content = append(content, miniMaxURLContent("image_url", "image_url", request.LastFrame, "last_frame"))
	}
	for _, rawURL := range request.ReferenceImages {
		content = append(content, miniMaxURLContent("image_url", "image_url", rawURL, "reference_image"))
	}
	if request.VideoReference != "" {
		content = append(content, miniMaxURLContent("video_url", "video_url", request.VideoReference, "reference_video"))
	}
	if request.AudioReference != "" {
		content = append(content, miniMaxURLContent("audio_url", "audio_url", request.AudioReference, "reference_audio"))
	}
	payload := map[string]any{
		"model":      "MiniMax-H3",
		"content":    content,
		"duration":   request.DurationSeconds,
		"resolution": "2K",
	}
	if request.FirstFrame == "" && request.LastFrame == "" {
		payload["ratio"] = request.AspectRatio
	}
	resp, err := c.request(ctx, http.MethodPost, "/v2/video_generation", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		TaskID string `json:"task_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&body); err != nil || strings.TrimSpace(body.TaskID) == "" {
		return nil, fmt.Errorf("minimax video queue: invalid response")
	}
	return &QueueResult{ProviderModel: "MiniMax-H3", QueueID: body.TaskID}, nil
}

func miniMaxURLContent(kind, field, rawURL, role string) map[string]any {
	return map[string]any{
		"type": kind,
		field:  map[string]any{"url": rawURL},
		"role": role,
	}
}

func (c *MiniMaxClient) Retrieve(ctx context.Context, _ string, queueID string) (*PollResult, error) {
	resp, err := c.request(ctx, http.MethodGet, "/v2/query/video_generation/"+strings.TrimSpace(queueID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Task struct {
			Status  string `json:"status"`
			Content struct {
				URL string `json:"url"`
			} `json:"content"`
		} `json:"task"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&body); err != nil {
		return nil, fmt.Errorf("minimax video retrieve: invalid response")
	}
	status := strings.ToUpper(strings.TrimSpace(body.Task.Status))
	switch status {
	case "PENDING", "PROCESSING", "RUNNING", "QUEUED":
		return &PollResult{State: PollProcessing, ProviderStatus: status}, nil
	case "SUCCEEDED", "COMPLETED":
		if strings.TrimSpace(body.Task.Content.URL) == "" {
			return nil, fmt.Errorf("minimax video retrieve: missing video URL")
		}
		return &PollResult{State: PollCompleted, ProviderStatus: status, DownloadURL: body.Task.Content.URL}, nil
	case "FAILED", "CANCELLED", "CANCELED", "EXPIRED":
		return &PollResult{State: PollFailed, ProviderStatus: status}, nil
	default:
		return nil, fmt.Errorf("minimax video retrieve: unknown status")
	}
}

func (c *MiniMaxClient) Download(ctx context.Context, rawURL string) (*PollResult, error) {
	return downloadVideo(ctx, c.httpc, rawURL, c.ID(), nil)
}

func (c *MiniMaxClient) Complete(context.Context, string, string) error { return nil }

func (c *MiniMaxClient) request(ctx context.Context, method, path string, payload map[string]any) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("minimax video provider is not configured")
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
		return nil, fmt.Errorf("minimax video request failed: %w", err)
	}
	return resp, nil
}
