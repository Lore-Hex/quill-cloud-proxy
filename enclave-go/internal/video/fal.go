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

const (
	defaultFALVideoBaseURL = "https://queue.fal.run"
	falH3MaxModelID        = "minimax/h3-max"
	falH3MaxRoot           = "minimax/h3-max"
	maxFALVideoBytes       = 32 * 1024 * 1024
)

type FALVideoClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewFALVideoClient(apiKey string, httpc *http.Client) *FALVideoClient {
	return NewFALVideoClientAt(apiKey, defaultFALVideoBaseURL, httpc)
}

func NewFALVideoClientAt(apiKey, baseURL string, httpc *http.Client) *FALVideoClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &FALVideoClient{
		apiKey: strings.TrimSpace(apiKey), baseURL: strings.TrimRight(baseURL, "/"), httpc: httpc,
	}
}

func (c *FALVideoClient) ID() string    { return "fal" }
func (c *FALVideoClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *FALVideoClient) Supports(request *ResolvedRequest) bool {
	if request == nil || request.Model.ID != falH3MaxModelID ||
		request.NegativePrompt != "" || len(request.ReferenceImages) > 0 ||
		request.AudioReference != "" || request.VideoReference != "" {
		return false
	}
	if request.LastFrame != "" && request.FirstFrame == "" {
		return false
	}
	switch strings.ToLower(request.Resolution) {
	case "480p", "768p":
		return true
	default:
		return false
	}
}

func (c *FALVideoClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("fal video provider does not support this request")
	}
	rate := 50_000
	switch strings.ToLower(request.Resolution) {
	case "480p":
	case "768p":
		rate = 80_000
	default:
		return 0, fmt.Errorf("fal video provider does not support this resolution")
	}
	// Use fal's standard, non-promotional list price. A temporary launch
	// discount must not create an automatic undercharge when it expires.
	return staticCustomerQuote(rate, request.DurationSeconds, 0)
}

func (c *FALVideoClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("fal video provider does not support this request")
	}
	providerModel := falH3MaxRoot + "/text-to-video"
	payload := map[string]any{
		"prompt":                request.Prompt,
		"duration":              request.DurationSeconds,
		"resolution":            strings.ToUpper(request.Resolution),
		"enable_safety_checker": true,
		"prompt_expansion_mode": "balanced",
		"sync_mode":             true,
	}
	if request.Seed != nil {
		payload["seed"] = *request.Seed
	}
	if request.FirstFrame == "" {
		payload["aspect_ratio"] = request.AspectRatio
	} else {
		providerModel = falH3MaxRoot + "/image-to-video"
		payload["image_url"] = request.FirstFrame
		if request.LastFrame != "" {
			payload["end_image_url"] = request.LastFrame
		}
	}
	resp, err := c.request(ctx, http.MethodPost, "/"+providerModel, payload)
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&body); err != nil || !validFALRequestID(body.RequestID) {
		return nil, fmt.Errorf("fal video queue: invalid response")
	}
	return &QueueResult{ProviderModel: providerModel, QueueID: body.RequestID}, nil
}

func (c *FALVideoClient) Retrieve(ctx context.Context, providerModel string, queueID string) (*PollResult, error) {
	if providerModel != falH3MaxRoot+"/text-to-video" && providerModel != falH3MaxRoot+"/image-to-video" {
		return nil, falPermanentResultError()
	}
	queueID = strings.TrimSpace(queueID)
	if !validFALRequestID(queueID) {
		return nil, fmt.Errorf("fal video retrieve: invalid request id")
	}
	resp, err := c.request(ctx, http.MethodGet, "/"+falH3MaxRoot+"/requests/"+queueID+"/status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var statusBody struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&statusBody); err != nil {
		return nil, fmt.Errorf("fal video retrieve: invalid status response")
	}
	status := strings.ToUpper(strings.TrimSpace(statusBody.Status))
	switch status {
	case "IN_QUEUE", "IN_PROGRESS", "PENDING", "PROCESSING", "RUNNING", "QUEUED":
		return &PollResult{State: PollProcessing, ProviderStatus: status}, nil
	case "FAILED", "CANCELLED", "CANCELED", "EXPIRED":
		return &PollResult{State: PollFailed, ProviderStatus: status}, nil
	case "COMPLETED", "SUCCEEDED":
		return c.retrieveCompleted(ctx, queueID, status)
	default:
		return nil, fmt.Errorf("fal video retrieve: unknown status")
	}
}

func (c *FALVideoClient) retrieveCompleted(ctx context.Context, queueID, status string) (*PollResult, error) {
	resp, err := c.request(ctx, http.MethodGet, "/"+falH3MaxRoot+"/requests/"+queueID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Video struct {
			URL         string `json:"url"`
			ContentType string `json:"content_type"`
			FileSize    int64  `json:"file_size"`
		} `json:"video"`
	}
	const maxJSONBytes = maxFALVideoBytes*4/3 + 1024*1024
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBytes+1)).Decode(&body); err != nil {
		return nil, fmt.Errorf("fal video retrieve: invalid result response")
	}
	if body.Video.ContentType != "video/mp4" || body.Video.FileSize <= 0 || body.Video.FileSize > maxFALVideoBytes {
		return nil, falPermanentResultError()
	}
	const prefix = "data:video/mp4;base64,"
	rawURL := strings.TrimSpace(body.Video.URL)
	encoded := strings.TrimPrefix(rawURL, prefix)
	if encoded == rawURL || encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maxFALVideoBytes) {
		return nil, falPermanentResultError()
	}
	decodedSize, err := io.Copy(
		io.Discard,
		io.LimitReader(base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded)), maxFALVideoBytes+1),
	)
	if err != nil || decodedSize != body.Video.FileSize {
		return nil, falPermanentResultError()
	}
	return &PollResult{
		State: PollCompleted, ProviderStatus: status,
		Body: io.NopCloser(base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))), ContentType: "video/mp4",
	}, nil
}

func (c *FALVideoClient) Download(context.Context, string) (*PollResult, error) {
	return nil, fmt.Errorf("fal video download: inline result required")
}

func (c *FALVideoClient) Complete(context.Context, string, string) error { return nil }

func falPermanentResultError() error {
	return &HTTPError{Provider: "fal", Status: http.StatusBadGateway, Retryable: false}
}

func (c *FALVideoClient) request(ctx context.Context, method, path string, payload map[string]any) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("fal video provider is not configured")
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
	req.Header.Set("Authorization", "Key "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fal video request failed: %w", err)
	}
	return resp, nil
}

func validFALRequestID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}
