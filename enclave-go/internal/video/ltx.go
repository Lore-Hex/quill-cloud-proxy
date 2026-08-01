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

const defaultLTXVideoBaseURL = "https://api.ltx.io"

type LTXClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewLTXClient(apiKey string, httpc *http.Client) *LTXClient {
	return NewLTXClientAt(apiKey, defaultLTXVideoBaseURL, httpc)
}

func NewLTXClientAt(apiKey, baseURL string, httpc *http.Client) *LTXClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &LTXClient{
		apiKey: strings.TrimSpace(apiKey), baseURL: strings.TrimRight(baseURL, "/"), httpc: httpc,
	}
}

func (c *LTXClient) ID() string    { return "ltx" }
func (c *LTXClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *LTXClient) Supports(request *ResolvedRequest) bool {
	if request == nil || (request.Model.ID != "lightricks/ltx-2.3" && request.Model.ID != "lightricks/ltx-2.3-fast") {
		return false
	}
	if request.NegativePrompt != "" || request.Seed != nil || len(request.ReferenceImages) > 0 ||
		request.AudioReference != "" || request.VideoReference != "" {
		return false
	}
	return request.LastFrame == "" || request.FirstFrame != ""
}

func (c *LTXClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("ltx video provider does not support this request")
	}
	rate := 80_000
	if request.Model.ID == "lightricks/ltx-2.3-fast" {
		rate = 60_000
	}
	switch strings.ToLower(request.Resolution) {
	case "1440p":
		rate *= 2
	case "2160p", "4k":
		rate *= 4
	case "1080p":
	default:
		return 0, fmt.Errorf("ltx video provider does not support this resolution")
	}
	return staticCustomerQuote(rate, request.DurationSeconds, 0)
}

func (c *LTXClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("ltx video provider does not support this request")
	}
	model := "ltx-2-3-pro"
	if request.Model.ID == "lightricks/ltx-2.3-fast" {
		model = "ltx-2-3-fast"
	}
	mode := "text-to-video"
	payload := map[string]any{
		"prompt": request.Prompt, "model": model, "duration": request.DurationSeconds,
		"resolution":     ltxResolution(request.Resolution, request.AspectRatio),
		"generate_audio": request.GenerateAudio,
	}
	if request.FirstFrame != "" {
		mode = "image-to-video"
		payload["image_uri"] = request.FirstFrame
		if request.LastFrame != "" {
			payload["last_frame_uri"] = request.LastFrame
		}
	}
	resp, err := c.request(ctx, http.MethodPost, "/v2/"+mode, payload)
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
		return nil, fmt.Errorf("ltx video queue: invalid response")
	}
	return &QueueResult{ProviderModel: model + "|" + mode, QueueID: body.ID}, nil
}

func ltxResolution(resolution, aspect string) string {
	landscape := strings.EqualFold(aspect, "16:9")
	switch strings.ToLower(resolution) {
	case "1440p":
		if landscape {
			return "2560x1440"
		}
		return "1440x2560"
	case "2160p", "4k":
		if landscape {
			return "3840x2160"
		}
		return "2160x3840"
	default:
		if landscape {
			return "1920x1080"
		}
		return "1080x1920"
	}
}

func (c *LTXClient) Retrieve(ctx context.Context, providerModel, queueID string) (*PollResult, error) {
	mode := "text-to-video"
	if strings.HasSuffix(providerModel, "|image-to-video") {
		mode = "image-to-video"
	}
	resp, err := c.request(ctx, http.MethodGet, "/v2/"+mode+"/"+strings.TrimSpace(queueID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Status string `json:"status"`
		Result struct {
			VideoURL string `json:"video_url"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&body); err != nil {
		return nil, fmt.Errorf("ltx video retrieve: invalid response")
	}
	status := strings.ToUpper(strings.TrimSpace(body.Status))
	switch status {
	case "PENDING", "PROCESSING":
		return &PollResult{State: PollProcessing, ProviderStatus: status}, nil
	case "COMPLETED":
		if strings.TrimSpace(body.Result.VideoURL) == "" {
			return nil, fmt.Errorf("ltx video retrieve: missing video URL")
		}
		return &PollResult{State: PollCompleted, ProviderStatus: status, DownloadURL: body.Result.VideoURL}, nil
	case "FAILED", "CANCELLED", "CANCELED", "EXPIRED":
		return &PollResult{State: PollFailed, ProviderStatus: status}, nil
	default:
		return nil, fmt.Errorf("ltx video retrieve: unknown status")
	}
}

func (c *LTXClient) Download(ctx context.Context, rawURL string) (*PollResult, error) {
	return downloadVideo(ctx, c.httpc, rawURL, c.ID(), nil)
}

func (c *LTXClient) Complete(context.Context, string, string) error { return nil }

func (c *LTXClient) request(ctx context.Context, method, path string, payload map[string]any) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("ltx video provider is not configured")
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
		return nil, fmt.Errorf("ltx video request failed: %w", err)
	}
	return resp, nil
}
