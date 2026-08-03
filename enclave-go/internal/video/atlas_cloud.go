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

const defaultAtlasCloudVideoBaseURL = "https://api.atlascloud.ai"

type AtlasCloudVideoClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewAtlasCloudVideoClient(apiKey string, httpc *http.Client) *AtlasCloudVideoClient {
	return NewAtlasCloudVideoClientAt(apiKey, defaultAtlasCloudVideoBaseURL, httpc)
}

func NewAtlasCloudVideoClientAt(apiKey, baseURL string, httpc *http.Client) *AtlasCloudVideoClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &AtlasCloudVideoClient{
		apiKey: strings.TrimSpace(apiKey), baseURL: strings.TrimRight(baseURL, "/"), httpc: httpc,
	}
}

func (c *AtlasCloudVideoClient) ID() string    { return "atlas-cloud" }
func (c *AtlasCloudVideoClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *AtlasCloudVideoClient) Supports(request *ResolvedRequest) bool {
	if request == nil || request.Model.ID != "minimax/hailuo-3" ||
		request.DurationSeconds < 5 || request.DurationSeconds > 15 ||
		!strings.EqualFold(request.Resolution, "2K") ||
		request.NegativePrompt != "" || request.Seed != nil {
		return false
	}
	hasReferences := len(request.ReferenceImages) > 0 || request.AudioReference != "" || request.VideoReference != ""
	if hasReferences {
		// Atlas requires at least one image or video and has a separate reference
		// contract. Mixed frame/reference requests remain on another H3 provider.
		return request.FirstFrame == "" && request.LastFrame == "" &&
			(len(request.ReferenceImages) > 0 || request.VideoReference != "")
	}
	return request.LastFrame == "" || request.FirstFrame != ""
}

func (c *AtlasCloudVideoClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("atlas-cloud video provider does not support this request")
	}
	return staticCustomerQuote(140_000, request.DurationSeconds, 0)
}

func (c *AtlasCloudVideoClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("atlas-cloud video provider does not support this request")
	}
	providerModel, payload := atlasCloudH3Payload(request)
	resp, err := c.request(ctx, http.MethodPost, "/api/v1/model/generateVideo", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	prediction, err := decodeAtlasCloudPrediction(resp.Body)
	if err != nil || strings.TrimSpace(prediction.ID) == "" {
		return nil, fmt.Errorf("atlas-cloud video queue: invalid response")
	}
	return &QueueResult{ProviderModel: providerModel, QueueID: prediction.ID}, nil
}

func atlasCloudH3Payload(request *ResolvedRequest) (string, map[string]any) {
	payload := map[string]any{
		"prompt": request.Prompt, "resolution": "2K", "duration": request.DurationSeconds,
	}
	switch {
	case len(request.ReferenceImages) > 0 || request.AudioReference != "" || request.VideoReference != "":
		providerModel := "minimax/h3/reference-to-video"
		payload["model"] = providerModel
		payload["ratio"] = "adaptive"
		refers := make([]map[string]string, 0, len(request.ReferenceImages)+2)
		for _, rawURL := range request.ReferenceImages {
			refers = append(refers, map[string]string{"url": rawURL, "type": "image"})
		}
		if request.VideoReference != "" {
			refers = append(refers, map[string]string{"url": request.VideoReference, "type": "video"})
		}
		if request.AudioReference != "" {
			refers = append(refers, map[string]string{"url": request.AudioReference, "type": "audio"})
		}
		payload["refers"] = refers
		return providerModel, payload
	case request.FirstFrame != "":
		providerModel := "minimax/h3/image-to-video"
		payload["model"] = providerModel
		payload["image"] = request.FirstFrame
		if request.LastFrame != "" {
			payload["end_image"] = request.LastFrame
		}
		payload["ratio"] = "adaptive"
		return providerModel, payload
	default:
		providerModel := "minimax/h3/text-to-video"
		payload["model"] = providerModel
		payload["ratio"] = request.AspectRatio
		return providerModel, payload
	}
}

type atlasCloudPrediction struct {
	ID      string   `json:"id"`
	Model   string   `json:"model"`
	Status  string   `json:"status"`
	Outputs []string `json:"outputs"`
}

func decodeAtlasCloudPrediction(reader io.Reader) (atlasCloudPrediction, error) {
	var body struct {
		ID      string                `json:"id"`
		Model   string                `json:"model"`
		Status  string                `json:"status"`
		Outputs []string              `json:"outputs"`
		Data    *atlasCloudPrediction `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(reader, 256*1024)).Decode(&body); err != nil {
		return atlasCloudPrediction{}, err
	}
	if body.Data != nil {
		return *body.Data, nil
	}
	return atlasCloudPrediction{ID: body.ID, Model: body.Model, Status: body.Status, Outputs: body.Outputs}, nil
}

func (c *AtlasCloudVideoClient) Retrieve(ctx context.Context, _ string, queueID string) (*PollResult, error) {
	resp, err := c.request(ctx, http.MethodGet, "/api/v1/model/prediction/"+strings.TrimSpace(queueID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	prediction, err := decodeAtlasCloudPrediction(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("atlas-cloud video retrieve: invalid response")
	}
	status := strings.ToLower(strings.TrimSpace(prediction.Status))
	switch status {
	case "created", "pending", "queued", "processing", "running":
		return &PollResult{State: PollProcessing, ProviderStatus: status}, nil
	case "completed", "succeeded":
		if len(prediction.Outputs) == 0 || strings.TrimSpace(prediction.Outputs[0]) == "" {
			return nil, fmt.Errorf("atlas-cloud video retrieve: missing video URL")
		}
		return &PollResult{
			State: PollCompleted, ProviderStatus: status, DownloadURL: prediction.Outputs[0],
		}, nil
	case "failed", "cancelled", "canceled", "expired":
		return &PollResult{State: PollFailed, ProviderStatus: status}, nil
	default:
		return nil, fmt.Errorf("atlas-cloud video retrieve: unknown status")
	}
}

func (c *AtlasCloudVideoClient) Download(ctx context.Context, rawURL string) (*PollResult, error) {
	return downloadVideo(ctx, c.httpc, rawURL, c.ID(), nil)
}

func (c *AtlasCloudVideoClient) Complete(context.Context, string, string) error { return nil }

func (c *AtlasCloudVideoClient) request(
	ctx context.Context,
	method string,
	path string,
	payload map[string]any,
) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("atlas-cloud video provider is not configured")
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
		return nil, fmt.Errorf("atlas-cloud video request failed: %w", err)
	}
	return resp, nil
}
