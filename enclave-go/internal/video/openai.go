package video

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

const defaultOpenAIVideoBaseURL = "https://api.openai.com/v1"

type OpenAIVideoClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewOpenAIVideoClient(apiKey string, httpc *http.Client) *OpenAIVideoClient {
	return NewOpenAIVideoClientAt(apiKey, defaultOpenAIVideoBaseURL, httpc)
}

func NewOpenAIVideoClientAt(apiKey, baseURL string, httpc *http.Client) *OpenAIVideoClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &OpenAIVideoClient{
		apiKey: strings.TrimSpace(apiKey), baseURL: strings.TrimRight(baseURL, "/"), httpc: httpc,
	}
}

func (c *OpenAIVideoClient) ID() string    { return "openai" }
func (c *OpenAIVideoClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *OpenAIVideoClient) Supports(request *ResolvedRequest) bool {
	if request == nil || (request.Model.ID != "openai/sora-2" && request.Model.ID != "openai/sora-2-pro") {
		return false
	}
	// OpenAI's image-reference input is multipart file data, not a remote URL.
	// URL-based image requests stay on an authorized fallback route rather than
	// making the gateway fetch arbitrary user URLs through this adapter.
	return request.FirstFrame == "" && request.LastFrame == "" && len(request.ReferenceImages) == 0 &&
		request.AudioReference == "" && request.VideoReference == "" &&
		request.NegativePrompt == "" && request.Seed == nil
}

func (c *OpenAIVideoClient) QuoteResolved(_ context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("openai video provider does not support this request")
	}
	rate := 100_000
	if request.Model.ID == "openai/sora-2-pro" {
		rate = 300_000
		if strings.EqualFold(request.Resolution, "1024p") {
			rate = 500_000
		}
	}
	return staticCustomerQuote(rate, request.DurationSeconds, 0)
}

func (c *OpenAIVideoClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("openai video provider does not support this request")
	}
	providerModel := strings.TrimPrefix(request.Model.ID, "openai/")
	var encoded bytes.Buffer
	form := multipart.NewWriter(&encoded)
	fields := map[string]string{
		"model": providerModel, "prompt": request.Prompt,
		"seconds": fmt.Sprintf("%d", request.DurationSeconds),
		"size":    openAIVideoSize(request.Resolution, request.AspectRatio),
	}
	for key, value := range fields {
		if err := form.WriteField(key, value); err != nil {
			return nil, fmt.Errorf("openai video queue: encode request")
		}
	}
	if err := form.Close(); err != nil {
		return nil, fmt.Errorf("openai video queue: encode request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/videos", &encoded)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", form.FormDataContentType())
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai video request failed: %w", err)
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&body); err != nil || strings.TrimSpace(body.ID) == "" {
		return nil, fmt.Errorf("openai video queue: invalid response")
	}
	return &QueueResult{ProviderModel: providerModel, QueueID: body.ID}, nil
}

func openAIVideoSize(resolution, aspect string) string {
	landscape := strings.EqualFold(aspect, "16:9")
	if strings.EqualFold(resolution, "1024p") {
		if landscape {
			return "1792x1024"
		}
		return "1024x1792"
	}
	if landscape {
		return "1280x720"
	}
	return "720x1280"
}

func (c *OpenAIVideoClient) Retrieve(ctx context.Context, _ string, queueID string) (*PollResult, error) {
	resp, err := c.request(ctx, http.MethodGet, "/videos/"+strings.TrimSpace(queueID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&body); err != nil {
		return nil, fmt.Errorf("openai video retrieve: invalid response")
	}
	status := strings.ToUpper(strings.TrimSpace(body.Status))
	switch status {
	case "QUEUED", "PENDING", "IN_PROGRESS", "PROCESSING":
		return &PollResult{State: PollProcessing, ProviderStatus: status}, nil
	case "COMPLETED", "SUCCEEDED":
		return &PollResult{
			State: PollCompleted, ProviderStatus: status, DownloadURL: "openai-video:" + queueID,
		}, nil
	case "FAILED", "CANCELLED", "CANCELED", "EXPIRED":
		return &PollResult{State: PollFailed, ProviderStatus: status}, nil
	default:
		return nil, fmt.Errorf("openai video retrieve: unknown status")
	}
}

func (c *OpenAIVideoClient) Download(ctx context.Context, reference string) (*PollResult, error) {
	queueID := strings.TrimPrefix(strings.TrimSpace(reference), "openai-video:")
	if queueID == "" || queueID == reference {
		return nil, fmt.Errorf("openai video download: invalid reference")
	}
	resp, err := c.request(ctx, http.MethodGet, "/videos/"+queueID+"/content")
	if err != nil {
		return nil, err
	}
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		resp.Body.Close()
		return nil, err
	}
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "video/mp4"
	}
	return &PollResult{
		State: PollCompleted, ProviderStatus: "COMPLETED", Body: resp.Body, ContentType: contentType,
	}, nil
}

func (c *OpenAIVideoClient) Complete(ctx context.Context, _ string, queueID string) error {
	resp, err := c.request(ctx, http.MethodDelete, "/videos/"+strings.TrimSpace(queueID))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return requireProviderSuccess(c.ID(), resp)
}

func (c *OpenAIVideoClient) request(ctx context.Context, method, path string) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("openai video provider is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai video request failed: %w", err)
	}
	return resp, nil
}
