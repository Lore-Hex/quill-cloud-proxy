package video

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const defaultGoogleVideoBaseURL = "https://generativelanguage.googleapis.com/v1beta"

type GoogleVeoClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewGoogleVeoClient(apiKey string, httpc *http.Client) *GoogleVeoClient {
	return NewGoogleVeoClientAt(apiKey, defaultGoogleVideoBaseURL, httpc)
}

func NewGoogleVeoClientAt(apiKey, baseURL string, httpc *http.Client) *GoogleVeoClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &GoogleVeoClient{apiKey: strings.TrimSpace(apiKey), baseURL: strings.TrimRight(baseURL, "/"), httpc: httpc}
}

func (c *GoogleVeoClient) ID() string    { return "google-ai-studio" }
func (c *GoogleVeoClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *GoogleVeoClient) Supports(request *ResolvedRequest) bool {
	if request == nil || (request.Model.ID != "google/veo-3.1" && request.Model.ID != "google/veo-3.1-fast") {
		return false
	}
	if request.NegativePrompt != "" {
		return false
	}
	if len(request.ReferenceImages) > 0 || request.AudioReference != "" || request.VideoReference != "" {
		return false
	}
	if request.FirstFrame != "" && !strings.HasPrefix(request.FirstFrame, "data:") {
		return false
	}
	if request.LastFrame != "" && !strings.HasPrefix(request.LastFrame, "data:") {
		return false
	}
	return request.GenerateAudio
}

func (c *GoogleVeoClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("google veo provider does not support this request")
	}
	rate := 400_000
	if request.Model.ID == "google/veo-3.1-fast" {
		switch strings.ToLower(request.Resolution) {
		case "720p":
			rate = 100_000
		case "1080p":
			rate = 120_000
		case "4k":
			rate = 300_000
		}
	} else if strings.EqualFold(request.Resolution, "4k") {
		rate = 600_000
	}
	return staticCustomerQuote(rate, request.DurationSeconds, 0)
}

func (c *GoogleVeoClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("google veo provider does not support this request")
	}
	nativeModel := "veo-3.1-generate-preview"
	if request.Model.ID == "google/veo-3.1-fast" {
		nativeModel = "veo-3.1-fast-generate-preview"
	}
	instance := map[string]any{"prompt": request.Prompt}
	if request.FirstFrame != "" {
		image, err := googleInlineData(request.FirstFrame)
		if err != nil {
			return nil, err
		}
		instance["image"] = image
	}
	if request.LastFrame != "" {
		image, err := googleInlineData(request.LastFrame)
		if err != nil {
			return nil, err
		}
		instance["lastFrame"] = image
	}
	parameters := map[string]any{
		"aspectRatio":     request.AspectRatio,
		"durationSeconds": request.DurationSeconds,
		"resolution":      strings.ToLower(request.Resolution),
		"numberOfVideos":  1,
	}
	if request.Seed != nil {
		parameters["seed"] = *request.Seed
	}
	payload := map[string]any{"instances": []map[string]any{instance}, "parameters": parameters}
	resp, err := c.request(ctx, http.MethodPost, "/models/"+nativeModel+":predictLongRunning", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		return nil, fmt.Errorf("google veo queue: invalid response")
	}
	return &QueueResult{ProviderModel: nativeModel, QueueID: body.Name}, nil
}

func googleInlineData(raw string) (map[string]any, error) {
	prefix, encoded, ok := strings.Cut(raw, ",")
	if !ok || !strings.HasPrefix(prefix, "data:image/") || !strings.HasSuffix(strings.ToLower(prefix), ";base64") {
		return nil, fmt.Errorf("google veo image inputs must be base64 data URLs")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > 20*1024*1024 {
		return nil, fmt.Errorf("google veo image data is invalid")
	}
	mimeType := strings.TrimPrefix(strings.TrimSuffix(prefix, ";base64"), "data:")
	return map[string]any{"inlineData": map[string]any{"mimeType": mimeType, "data": encoded}}, nil
}

func (c *GoogleVeoClient) Retrieve(ctx context.Context, _ string, queueID string) (*PollResult, error) {
	path := "/" + strings.TrimLeft(strings.TrimSpace(queueID), "/")
	resp, err := c.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Done  bool `json:"done"`
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
		Response struct {
			GenerateVideoResponse struct {
				GeneratedSamples []struct {
					Video struct {
						URI string `json:"uri"`
					} `json:"video"`
				} `json:"generatedSamples"`
			} `json:"generateVideoResponse"`
		} `json:"response"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&body); err != nil {
		return nil, fmt.Errorf("google veo retrieve: invalid response")
	}
	if !body.Done {
		return &PollResult{State: PollProcessing, ProviderStatus: "RUNNING"}, nil
	}
	if body.Error != nil {
		return &PollResult{State: PollFailed, ProviderStatus: "FAILED"}, nil
	}
	if len(body.Response.GenerateVideoResponse.GeneratedSamples) == 0 {
		return nil, fmt.Errorf("google veo retrieve: missing generated video")
	}
	videoURL := strings.TrimSpace(body.Response.GenerateVideoResponse.GeneratedSamples[0].Video.URI)
	if videoURL == "" {
		return nil, fmt.Errorf("google veo retrieve: missing video URL")
	}
	return &PollResult{State: PollCompleted, ProviderStatus: "SUCCEEDED", DownloadURL: videoURL}, nil
}

func (c *GoogleVeoClient) Download(ctx context.Context, rawURL string) (*PollResult, error) {
	headers := make(http.Header)
	headers.Set("x-goog-api-key", c.apiKey)
	return downloadVideo(ctx, c.httpc, rawURL, c.ID(), headers)
}

func (c *GoogleVeoClient) Complete(context.Context, string, string) error { return nil }

func (c *GoogleVeoClient) request(ctx context.Context, method, path string, payload map[string]any) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("google veo provider is not configured")
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
	req.Header.Set("x-goog-api-key", c.apiKey)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google veo request failed: %w", err)
	}
	return resp, nil
}
