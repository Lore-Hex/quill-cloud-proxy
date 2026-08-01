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

const defaultAlibabaVideoBaseURL = "https://ws-el6e4bpnggpx7g88.eu-central-1.maas.aliyuncs.com"

type AlibabaClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewAlibabaClient(apiKey string, httpc *http.Client) *AlibabaClient {
	return NewAlibabaClientAt(apiKey, defaultAlibabaVideoBaseURL, httpc)
}

func NewAlibabaClientAt(apiKey, baseURL string, httpc *http.Client) *AlibabaClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &AlibabaClient{
		apiKey:  strings.TrimSpace(apiKey),
		baseURL: strings.TrimRight(baseURL, "/"),
		httpc:   httpc,
	}
}

func (c *AlibabaClient) ID() string    { return "alibaba" }
func (c *AlibabaClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *AlibabaClient) Supports(request *ResolvedRequest) bool {
	if request == nil || request.Model.ID != "alibaba/wan-2.7" {
		return false
	}
	if len(request.ReferenceImages) > 0 {
		return false
	}
	return !(request.FirstFrame != "" && request.VideoReference != "")
}

func (c *AlibabaClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("alibaba video provider does not support this request")
	}
	rate := 100_000
	if strings.EqualFold(request.Resolution, "1080p") {
		rate = 150_000
	}
	return staticCustomerQuote(rate, request.DurationSeconds, 0)
}

func (c *AlibabaClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("alibaba video provider does not support this request")
	}
	providerModel := "wan2.7-t2v"
	input := map[string]any{"prompt": request.Prompt}
	if request.NegativePrompt != "" {
		input["negative_prompt"] = request.NegativePrompt
	}
	media := make([]map[string]any, 0, 4)
	if request.FirstFrame != "" {
		providerModel = "wan2.7-i2v"
		media = append(media, map[string]any{"type": "first_frame", "url": request.FirstFrame})
	}
	if request.LastFrame != "" {
		providerModel = "wan2.7-i2v"
		media = append(media, map[string]any{"type": "last_frame", "url": request.LastFrame})
	}
	if request.AudioReference != "" {
		if providerModel == "wan2.7-i2v" {
			media = append(media, map[string]any{"type": "driving_audio", "url": request.AudioReference})
		} else {
			input["audio_url"] = request.AudioReference
		}
	}
	if request.VideoReference != "" {
		providerModel = "wan2.7-i2v"
		media = append(media, map[string]any{"type": "first_clip", "url": request.VideoReference})
	}
	if len(media) > 0 {
		input["media"] = media
	}
	payload := map[string]any{
		"model": providerModel,
		"input": input,
		"parameters": map[string]any{
			"resolution":    strings.ToUpper(request.Resolution),
			"ratio":         request.AspectRatio,
			"duration":      request.DurationSeconds,
			"prompt_extend": true,
			"watermark":     false,
		},
	}
	if request.Seed != nil {
		payload["parameters"].(map[string]any)["seed"] = *request.Seed
	}
	resp, err := c.request(ctx, http.MethodPost, "/api/v1/services/aigc/video-generation/video-synthesis", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Output struct {
			TaskID string `json:"task_id"`
		} `json:"output"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&body); err != nil || strings.TrimSpace(body.Output.TaskID) == "" {
		return nil, fmt.Errorf("alibaba video queue: invalid response")
	}
	return &QueueResult{ProviderModel: providerModel, QueueID: body.Output.TaskID}, nil
}

func (c *AlibabaClient) Retrieve(ctx context.Context, _ string, queueID string) (*PollResult, error) {
	resp, err := c.request(ctx, http.MethodGet, "/api/v1/tasks/"+strings.TrimSpace(queueID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Output struct {
			TaskStatus string `json:"task_status"`
			VideoURL   string `json:"video_url"`
		} `json:"output"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&body); err != nil {
		return nil, fmt.Errorf("alibaba video retrieve: invalid response")
	}
	status := strings.ToUpper(strings.TrimSpace(body.Output.TaskStatus))
	switch status {
	case "PENDING", "RUNNING":
		return &PollResult{State: PollProcessing, ProviderStatus: status}, nil
	case "SUCCEEDED":
		if strings.TrimSpace(body.Output.VideoURL) == "" {
			return nil, fmt.Errorf("alibaba video retrieve: missing video URL")
		}
		return &PollResult{State: PollCompleted, ProviderStatus: status, DownloadURL: body.Output.VideoURL}, nil
	case "FAILED", "CANCELED", "CANCELLED", "UNKNOWN":
		return &PollResult{State: PollFailed, ProviderStatus: status}, nil
	default:
		return nil, fmt.Errorf("alibaba video retrieve: unknown status")
	}
}

func (c *AlibabaClient) Download(ctx context.Context, rawURL string) (*PollResult, error) {
	return downloadVideo(ctx, c.httpc, rawURL, c.ID(), nil)
}

func (c *AlibabaClient) Complete(context.Context, string, string) error { return nil }

func (c *AlibabaClient) request(ctx context.Context, method, path string, payload map[string]any) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("alibaba video provider is not configured")
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
		req.Header.Set("X-DashScope-Async", "enable")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("alibaba video request failed: %w", err)
	}
	return resp, nil
}
