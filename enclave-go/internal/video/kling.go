package video

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const defaultKlingVideoBaseURL = "https://api-singapore.klingai.com"

type KlingClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewKlingClient(apiKey string, httpc *http.Client) *KlingClient {
	return NewKlingClientAt(apiKey, defaultKlingVideoBaseURL, httpc)
}

func NewKlingClientAt(apiKey, baseURL string, httpc *http.Client) *KlingClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &KlingClient{
		apiKey: strings.TrimSpace(apiKey), baseURL: strings.TrimRight(baseURL, "/"), httpc: httpc,
	}
}

func (c *KlingClient) ID() string    { return "kling" }
func (c *KlingClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *KlingClient) Supports(request *ResolvedRequest) bool {
	if request == nil || (request.Model.ID != "kling/v3-pro" && request.Model.ID != "kling/o3-pro") {
		return false
	}
	if request.NegativePrompt != "" || request.Seed != nil || request.AudioReference != "" || request.VideoReference != "" {
		return false
	}
	if request.LastFrame != "" && request.FirstFrame == "" {
		return false
	}
	// The current TrustedRouter input contract exposes reference images only
	// for models that advertise that capability. Kling's basic V3 entries do
	// not, so keep this adapter strict until the Omni reference API is surfaced.
	return len(request.ReferenceImages) == 0
}

func (c *KlingClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("kling video provider does not support this request")
	}
	creditsPerSecond := 0
	switch strings.ToLower(request.Resolution) {
	case "720p":
		creditsPerSecond = 6
		if request.GenerateAudio {
			creditsPerSecond = 9
		}
	case "1080p":
		creditsPerSecond = 8
		if request.GenerateAudio {
			creditsPerSecond = 12
		}
	case "2160p", "4k":
		creditsPerSecond = 30
	default:
		return 0, fmt.Errorf("kling video provider does not support this resolution")
	}
	// Kling publishes 66 credits per USD. Round the upstream rate upward to
	// the nearest microdollar before applying TrustedRouter's integer fee.
	rateMicrodollars := (creditsPerSecond*1_000_000 + 65) / 66
	return staticCustomerQuote(rateMicrodollars, request.DurationSeconds, 0)
}

func (c *KlingClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("kling video provider does not support this request")
	}
	path := "/text-to-video/kling-3.0"
	providerModel := "kling-3.0|text"
	payload := map[string]any{
		"prompt": request.Prompt,
		"settings": map[string]any{
			"resolution":   strings.ToLower(request.Resolution),
			"aspect_ratio": request.AspectRatio,
			"duration":     request.DurationSeconds,
			"audio":        klingAudioSetting(request.GenerateAudio),
			"multi_shot":   false,
		},
		"options": map[string]any{"watermark_info": map[string]any{"enabled": false}},
	}
	if request.FirstFrame != "" {
		path = "/image-to-video/kling-3.0"
		providerModel = "kling-3.0|image"
		contents := []map[string]any{
			{"type": "prompt", "text": request.Prompt},
			{"type": "first_frame", "url": request.FirstFrame},
		}
		if request.LastFrame != "" {
			contents = append(contents, map[string]any{"type": "last_frame", "url": request.LastFrame})
		}
		payload = map[string]any{
			"contents": contents,
			"settings": map[string]any{
				"resolution": strings.ToLower(request.Resolution),
				"duration":   request.DurationSeconds,
				"audio":      klingAudioSetting(request.GenerateAudio),
				"multi_shot": false,
			},
			"options": map[string]any{"watermark_info": map[string]any{"enabled": false}},
		}
	}
	if request.Model.ID == "kling/o3-pro" {
		path = "/omni-video/kling-3.0-omni"
		providerModel = "kling-3.0-omni|omni"
		contents := []map[string]any{{"type": "prompt", "text": request.Prompt}}
		if request.FirstFrame != "" {
			contents = append(contents, map[string]any{"type": "first_frame", "url": request.FirstFrame})
		}
		if request.LastFrame != "" {
			contents = append(contents, map[string]any{"type": "last_frame", "url": request.LastFrame})
		}
		payload = map[string]any{
			"contents": contents,
			"settings": map[string]any{
				"resolution":   strings.ToLower(request.Resolution),
				"aspect_ratio": request.AspectRatio,
				"duration":     request.DurationSeconds,
				"audio":        klingAudioSetting(request.GenerateAudio),
				"multi_shot":   false,
			},
			"options": map[string]any{"watermark_info": map[string]any{"enabled": false}},
		}
	}

	resp, err := c.request(ctx, http.MethodPost, path, payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Code int `json:"code"`
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&body); err != nil || body.Code != 0 || strings.TrimSpace(body.Data.ID) == "" {
		return nil, fmt.Errorf("kling video queue: invalid response")
	}
	return &QueueResult{ProviderModel: providerModel, QueueID: body.Data.ID}, nil
}

func (c *KlingClient) Retrieve(ctx context.Context, _ string, queueID string) (*PollResult, error) {
	path := "/tasks?task_ids=" + url.QueryEscape(strings.TrimSpace(queueID))
	resp, err := c.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Code int `json:"code"`
		Data []struct {
			ID      string `json:"id"`
			Status  string `json:"status"`
			Message string `json:"message"`
			Outputs []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"outputs"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&body); err != nil || body.Code != 0 || len(body.Data) == 0 {
		return nil, fmt.Errorf("kling video retrieve: invalid response")
	}
	task := body.Data[0]
	status := strings.ToLower(strings.TrimSpace(task.Status))
	switch status {
	case "submitted", "processing", "pending", "running":
		return &PollResult{State: PollProcessing, ProviderStatus: strings.ToUpper(status)}, nil
	case "succeeded", "completed":
		for _, output := range task.Outputs {
			if strings.EqualFold(output.Type, "video") && strings.TrimSpace(output.URL) != "" {
				return &PollResult{State: PollCompleted, ProviderStatus: strings.ToUpper(status), DownloadURL: output.URL}, nil
			}
		}
		return nil, fmt.Errorf("kling video retrieve: missing video URL")
	case "failed", "cancelled", "canceled":
		return &PollResult{State: PollFailed, ProviderStatus: strings.ToUpper(status)}, nil
	default:
		return nil, fmt.Errorf("kling video retrieve: unknown status")
	}
}

func (c *KlingClient) Download(ctx context.Context, rawURL string) (*PollResult, error) {
	return downloadVideo(ctx, c.httpc, rawURL, c.ID(), nil)
}

func (c *KlingClient) Complete(context.Context, string, string) error { return nil }

func (c *KlingClient) request(ctx context.Context, method, path string, payload map[string]any) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("kling video provider is not configured")
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
		return nil, fmt.Errorf("kling video request failed: %w", err)
	}
	return resp, nil
}

func klingAudioSetting(generate bool) string {
	if generate {
		return "native"
	}
	return "off"
}
