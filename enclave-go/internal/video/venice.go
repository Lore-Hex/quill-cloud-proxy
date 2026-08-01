package video

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const defaultVeniceVideoBaseURL = "https://api.venice.ai/api/v1/video"

type VeniceClient struct {
	apiKey  string
	baseURL string
	httpc   *http.Client
}

func NewVeniceClient(apiKey string, httpc *http.Client) *VeniceClient {
	return NewVeniceClientAt(apiKey, defaultVeniceVideoBaseURL, httpc)
}

func NewVeniceClientAt(apiKey, baseURL string, httpc *http.Client) *VeniceClient {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &VeniceClient{apiKey: strings.TrimSpace(apiKey), baseURL: strings.TrimRight(baseURL, "/"), httpc: httpc}
}

func (c *VeniceClient) Enabled() bool { return c != nil && c.apiKey != "" }

func (c *VeniceClient) ID() string { return "venice" }

func (c *VeniceClient) Supports(request *ResolvedRequest) bool {
	return request != nil && !request.Model.DirectOnly && request.VeniceModel != ""
}

func (c *VeniceClient) QuoteResolved(ctx context.Context, request *ResolvedRequest) (int, error) {
	if !c.Supports(request) {
		return 0, fmt.Errorf("venice video provider does not support this request")
	}
	return c.Quote(ctx, request.VeniceQuotePayload())
}

func (c *VeniceClient) QueueResolved(ctx context.Context, request *ResolvedRequest) (*QueueResult, error) {
	if !c.Supports(request) {
		return nil, fmt.Errorf("venice video provider does not support this request")
	}
	return c.Queue(ctx, request.VeniceQueuePayload())
}

func (c *VeniceClient) Quote(ctx context.Context, payload map[string]any) (int, error) {
	resp, err := c.post(ctx, "/quote", payload)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if err := requireSuccess(resp); err != nil {
		return 0, err
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 64*1024))
	decoder.UseNumber()
	var body struct {
		Quote json.Number `json:"quote"`
	}
	if err := decoder.Decode(&body); err != nil {
		return 0, fmt.Errorf("venice video quote: invalid response")
	}
	upstream, err := dollarsToMicrodollars(string(body.Quote))
	if err != nil || upstream <= 0 {
		return 0, fmt.Errorf("venice video quote: invalid amount")
	}
	quoted, err := customerVideoPrice(upstream)
	if err != nil {
		return 0, fmt.Errorf("venice video quote: %w", err)
	}
	return quoted, nil
}

func (c *VeniceClient) Queue(ctx context.Context, payload map[string]any) (*QueueResult, error) {
	resp, err := c.post(ctx, "/queue", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := requireSuccess(resp); err != nil {
		return nil, err
	}
	var body struct {
		Model   string `json:"model"`
		QueueID string `json:"queue_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&body); err != nil {
		return nil, fmt.Errorf("venice video queue: invalid response")
	}
	if strings.TrimSpace(body.Model) == "" || strings.TrimSpace(body.QueueID) == "" {
		return nil, fmt.Errorf("venice video queue: missing job id")
	}
	return &QueueResult{ProviderModel: body.Model, QueueID: body.QueueID}, nil
}

func (c *VeniceClient) Retrieve(ctx context.Context, providerModel, queueID string) (*PollResult, error) {
	resp, err := c.post(ctx, "/retrieve", map[string]any{
		"model": providerModel, "queue_id": queueID, "delete_media_on_completion": false,
	})
	if err != nil {
		return nil, err
	}
	if err := requireSuccess(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "video/") || strings.HasPrefix(contentType, "application/octet-stream") {
		return &PollResult{State: PollCompleted, ProviderStatus: "COMPLETED", Body: resp.Body, ContentType: resp.Header.Get("Content-Type")}, nil
	}
	defer resp.Body.Close()
	var body struct {
		Status      string `json:"status"`
		DownloadURL string `json:"download_url"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&body); err != nil {
		return nil, fmt.Errorf("venice video retrieve: invalid response")
	}
	switch strings.ToUpper(body.Status) {
	case "PROCESSING", "PENDING", "QUEUED":
		return &PollResult{State: PollProcessing, ProviderStatus: strings.ToUpper(body.Status)}, nil
	case "COMPLETED":
		return &PollResult{State: PollCompleted, ProviderStatus: "COMPLETED", DownloadURL: body.DownloadURL}, nil
	case "FAILED", "ERROR":
		return &PollResult{State: PollFailed, ProviderStatus: strings.ToUpper(body.Status)}, nil
	default:
		return nil, fmt.Errorf("venice video retrieve: unknown status")
	}
}

func (c *VeniceClient) Complete(ctx context.Context, providerModel, queueID string) error {
	resp, err := c.post(ctx, "/complete", map[string]any{"model": providerModel, "queue_id": queueID})
	if err != nil {
		return err
	}
	if err := requireSuccess(resp); err != nil {
		resp.Body.Close()
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) || httpErr.Status != http.StatusBadRequest {
			return err
		}
		// Venice currently returns 400 from /complete for some VPS-backed
		// video models even though the queue remains retrievable. Its documented
		// delete-on-retrieve path is the reliable cleanup fallback. This runs
		// only after TrustedRouter has delivered the full response to the client.
		return c.deleteOnRetrieve(ctx, providerModel, queueID)
	}
	defer resp.Body.Close()
	var body struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&body); err != nil || !body.Success {
		return fmt.Errorf("venice video cleanup failed")
	}
	return nil
}

func (c *VeniceClient) deleteOnRetrieve(ctx context.Context, providerModel, queueID string) error {
	resp, err := c.post(ctx, "/retrieve", map[string]any{
		"model": providerModel, "queue_id": queueID, "delete_media_on_completion": true,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if err := requireSuccess(resp); err != nil {
		return err
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "video/") || strings.HasPrefix(contentType, "application/octet-stream") {
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return fmt.Errorf("venice video cleanup stream failed: %w", err)
		}
		return nil
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&body); err != nil {
		return fmt.Errorf("venice video cleanup: invalid response")
	}
	if strings.EqualFold(body.Status, "COMPLETED") {
		return nil
	}
	return fmt.Errorf("venice video cleanup is not ready")
}

func (c *VeniceClient) Download(ctx context.Context, rawURL string) (*PollResult, error) {
	return downloadVideo(ctx, c.httpc, rawURL, c.ID(), nil)
}

func (c *VeniceClient) post(ctx context.Context, path string, payload map[string]any) (*http.Response, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("venice video provider is not configured")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("venice video request failed: %w", err)
	}
	return resp, nil
}

func requireSuccess(resp *http.Response) error {
	return requireProviderSuccess("venice", resp)
}

func dollarsToMicrodollars(raw string) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "eE") {
		return 0, fmt.Errorf("invalid dollar amount")
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 {
		return 0, fmt.Errorf("invalid dollar amount")
	}
	whole := parts[0]
	if whole == "" {
		whole = "0"
	}
	wholeValue, err := parseDecimalDigits(whole)
	if err != nil {
		return 0, err
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
	}
	roundUp := false
	if len(fraction) > 6 {
		for _, digit := range fraction[6:] {
			if digit != '0' {
				roundUp = true
				break
			}
		}
		fraction = fraction[:6]
	}
	for len(fraction) < 6 {
		fraction += "0"
	}
	fractionValue, err := parseDecimalDigits(fraction)
	if err != nil {
		return 0, err
	}
	if wholeValue > (int(^uint(0)>>1)-fractionValue)/1_000_000 {
		return 0, fmt.Errorf("dollar amount is too large")
	}
	result := wholeValue*1_000_000 + fractionValue
	if roundUp {
		result++
	}
	return result, nil
}

func parseDecimalDigits(value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	result := 0
	maxInt := int(^uint(0) >> 1)
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("invalid dollar amount")
		}
		numeric := int(digit - '0')
		if result > (maxInt-numeric)/10 {
			return 0, fmt.Errorf("dollar amount is too large")
		}
		result = result*10 + numeric
	}
	return result, nil
}
