package video

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const bytePlusVideoBaseURL = "https://ark.ap-southeast.bytepluses.com/api/v3"
const bytePlusVideoCDN = "ark-acg-ap-southeast-1.tos-ap-southeast-1.volces.com"

var bytePlusVideoModels = map[string]string{
	"bytedance/seedance-2.5":      "dreamina-seedance-2-5-260628",
	"bytedance/seedance-2.0":      "dreamina-seedance-2-0-260128",
	"bytedance/seedance-2.0-fast": "dreamina-seedance-2-0-fast-260128",
}

var bytePlusTaskID = regexp.MustCompile(`^cgt-[A-Za-z0-9-]{1,100}$`)

type BytePlusClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewBytePlusClient(apiKey string, httpc *http.Client) *BytePlusClient {
	return NewBytePlusClientAt(apiKey, bytePlusVideoBaseURL, httpc)
}

func NewBytePlusClientAt(apiKey, baseURL string, httpc *http.Client) *BytePlusClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &BytePlusClient{strings.TrimSpace(apiKey), strings.TrimRight(baseURL, "/"), httpc}
}

func (c *BytePlusClient) ID() string    { return "byteplus" }
func (c *BytePlusClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *BytePlusClient) Supports(r *ResolvedRequest) bool {
	if r == nil || bytePlusVideoModels[r.Model.ID] == "" {
		return false
	}
	// These modes share one exact output-token tariff. Video input and higher
	// resolutions have different prices and must not inherit this tariff.
	return (r.Resolution == "480p" || r.Resolution == "720p") &&
		r.DurationSeconds >= 4 && r.DurationSeconds <= 15 &&
		r.VideoReference == "" && r.AudioReference == "" && r.NegativePrompt == "" &&
		r.LastFrame == "" && len(r.ReferenceImages) == 0
}

func (c *BytePlusClient) OutputTokenLimit(r *ResolvedRequest) (int, error) {
	if !c.Supports(r) {
		return 0, fmt.Errorf("byteplus video: unsupported input mode, duration, or resolution")
	}
	// Conservative reservation only; never the billed usage. Actual charges
	// use the completed task's integer completion_tokens at the frozen tariff.
	perSecond := 20_000
	if r.Resolution == "720p" {
		perSecond = 40_000
	}
	return perSecond * r.DurationSeconds, nil
}

func (c *BytePlusClient) QuoteResolved(_ context.Context, r *ResolvedRequest) (int, error) {
	_, err := c.OutputTokenLimit(r)
	return 0, err
}

func (c *BytePlusClient) QueueResolved(ctx context.Context, r *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(r) {
		return nil, fmt.Errorf("byteplus video: unsupported request")
	}
	content := []map[string]any{{"type": "text", "text": r.Prompt}}
	if r.FirstFrame != "" {
		content = append(content, map[string]any{"type": "image_url", "image_url": map[string]any{"url": r.FirstFrame}, "role": "first_frame"})
	}
	payload := map[string]any{"model": bytePlusVideoModels[r.Model.ID], "content": content,
		"duration": r.DurationSeconds, "resolution": r.Resolution, "generate_audio": r.GenerateAudio,
		"watermark": false}
	if r.AspectRatio != "" {
		payload["ratio"] = r.AspectRatio
		if r.AspectRatio == "source" {
			payload["ratio"] = "adaptive"
		}
	}
	if r.Seed != nil {
		payload["seed"] = *r.Seed
	}
	resp, err := c.request(ctx, http.MethodPost, "/contents/generations/tasks", payload)
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&body); err != nil || !bytePlusTaskID.MatchString(body.ID) {
		return nil, fmt.Errorf("byteplus video queue: invalid task id")
	}
	return &QueueResult{ProviderModel: bytePlusVideoModels[r.Model.ID], QueueID: body.ID}, nil
}

func (c *BytePlusClient) Retrieve(ctx context.Context, model, taskID string) (*PollResult, error) {
	if !bytePlusTaskID.MatchString(taskID) {
		return nil, fmt.Errorf("byteplus video: invalid task id")
	}
	resp, err := c.request(ctx, http.MethodGet, "/contents/generations/tasks/"+taskID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireProviderSuccess(c.ID(), resp); err != nil {
		return nil, err
	}
	var body struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Status  string `json:"status"`
		Content struct {
			VideoURL string `json:"video_url"`
		} `json:"content"`
		Usage struct {
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512<<10)).Decode(&body); err != nil || body.ID != taskID || body.Model != model {
		return nil, fmt.Errorf("byteplus video retrieve: invalid task identity or response")
	}
	result := &PollResult{ProviderStatus: body.Status}
	switch body.Status {
	case "queued", "running":
		result.State = PollProcessing
	case "failed", "cancelled", "expired":
		result.State = PollFailed
	case "succeeded":
		if body.Usage.CompletionTokens <= 0 || body.Usage.CompletionTokens > 2_000_000 {
			return nil, fmt.Errorf("byteplus video retrieve: missing or invalid completion_tokens")
		}
		if err := validateBytePlusDownload(body.Content.VideoURL); err != nil {
			return nil, fmt.Errorf("byteplus video retrieve: invalid download URL")
		}
		result.State, result.DownloadURL, result.OutputTokens = PollCompleted, body.Content.VideoURL, body.Usage.CompletionTokens
	default:
		return nil, fmt.Errorf("byteplus video retrieve: unknown status")
	}
	return result, nil
}

func (c *BytePlusClient) Download(ctx context.Context, rawURL string) (*PollResult, error) {
	if err := validateBytePlusDownload(rawURL); err != nil {
		return nil, err
	}
	// Enforce the same host on every hop, including redirects. No inference
	// credential is ever attached to the content download.
	client := *c.httpc
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = bytePlusDownloadTransport{transport}
	return downloadVideo(ctx, &client, rawURL, c.ID(), nil)
}

func validateBytePlusDownload(rawURL string) error {
	u, err := validateDownloadURL(rawURL)
	if err != nil || !strings.EqualFold(u.Hostname(), bytePlusVideoCDN) {
		return fmt.Errorf("byteplus video: unapproved download host")
	}
	return nil
}

type bytePlusDownloadTransport struct{ http.RoundTripper }

func (t bytePlusDownloadTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := validateBytePlusDownload(r.URL.String()); err != nil {
		return nil, err
	}
	return t.RoundTripper.RoundTrip(r)
}

func (c *BytePlusClient) Complete(ctx context.Context, _ string, taskID string) error {
	if !bytePlusTaskID.MatchString(taskID) {
		return fmt.Errorf("byteplus video: invalid task id")
	}
	resp, err := c.request(ctx, http.MethodDelete, "/contents/generations/tasks/"+taskID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return requireProviderSuccess(c.ID(), resp)
}

func (c *BytePlusClient) request(ctx context.Context, method, path string, payload map[string]any) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("byteplus video is not configured")
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("byteplus video: invalid payload")
		}
		body = bytes.NewReader(raw)
	}
	parsed, err := url.Parse(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("byteplus video: invalid API URL")
	}
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	client := *c.httpc
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client.Do(req)
}
