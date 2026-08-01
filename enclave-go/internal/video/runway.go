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

const defaultRunwayVideoBaseURL = "https://api.dev.runwayml.com"

type RunwayClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewRunwayClient(apiKey string, httpc *http.Client) *RunwayClient {
	return NewRunwayClientAt(apiKey, defaultRunwayVideoBaseURL, httpc)
}

func NewRunwayClientAt(apiKey, baseURL string, httpc *http.Client) *RunwayClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &RunwayClient{
		apiKey: strings.TrimSpace(apiKey), baseURL: strings.TrimRight(baseURL, "/"), httpc: httpc,
	}
}

func (c *RunwayClient) ID() string    { return "runway" }
func (c *RunwayClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *RunwayClient) Supports(request *ResolvedRequest) bool {
	return request != nil && request.Model.ID == "runway/gen-4.5" &&
		request.NegativePrompt == "" && request.Seed == nil && request.LastFrame == "" &&
		len(request.ReferenceImages) == 0 && request.AudioReference == "" && request.VideoReference == ""
}

func (c *RunwayClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("runway video provider does not support this request")
	}
	// Runway Gen-4.5 is 12 credits/s and API credits cost $0.01 each.
	return staticCustomerQuote(120_000, request.DurationSeconds, 0)
}

func (c *RunwayClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("runway video provider does not support this request")
	}
	mode := "text_to_video"
	payload := map[string]any{
		"model": "gen4.5", "promptText": request.Prompt,
		"ratio": runwayRatio(request.AspectRatio), "duration": request.DurationSeconds,
	}
	if request.FirstFrame != "" {
		mode = "image_to_video"
		payload["promptImage"] = request.FirstFrame
	}
	resp, err := c.request(ctx, http.MethodPost, "/v1/"+mode, payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&body); err != nil || strings.TrimSpace(body.ID) == "" {
		return nil, fmt.Errorf("runway video queue: invalid response")
	}
	return &QueueResult{ProviderModel: "gen4.5", QueueID: body.ID}, nil
}

func runwayRatio(aspect string) string {
	if strings.EqualFold(aspect, "9:16") {
		return "720:1280"
	}
	return "1280:720"
}

func (c *RunwayClient) Retrieve(ctx context.Context, _ string, queueID string) (*PollResult, error) {
	resp, err := c.request(ctx, http.MethodGet, "/v1/tasks/"+strings.TrimSpace(queueID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Status string   `json:"status"`
		Output []string `json:"output"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&body); err != nil {
		return nil, fmt.Errorf("runway video retrieve: invalid response")
	}
	status := strings.ToUpper(strings.TrimSpace(body.Status))
	switch status {
	case "PENDING", "THROTTLED", "RUNNING", "PROCESSING":
		return &PollResult{State: PollProcessing, ProviderStatus: status}, nil
	case "SUCCEEDED", "COMPLETED":
		if len(body.Output) == 0 || strings.TrimSpace(body.Output[0]) == "" {
			return nil, fmt.Errorf("runway video retrieve: missing video URL")
		}
		return &PollResult{State: PollCompleted, ProviderStatus: status, DownloadURL: body.Output[0]}, nil
	case "FAILED", "CANCELED", "CANCELLED":
		return &PollResult{State: PollFailed, ProviderStatus: status}, nil
	default:
		return nil, fmt.Errorf("runway video retrieve: unknown status")
	}
}

func (c *RunwayClient) Download(ctx context.Context, rawURL string) (*PollResult, error) {
	return downloadVideo(ctx, c.httpc, rawURL, c.ID(), nil)
}

func (c *RunwayClient) Complete(context.Context, string, string) error { return nil }

func (c *RunwayClient) request(ctx context.Context, method, path string, payload map[string]any) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("runway video provider is not configured")
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
	req.Header.Set("X-Runway-Version", "2024-11-06")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("runway video request failed: %w", err)
	}
	return resp, nil
}
