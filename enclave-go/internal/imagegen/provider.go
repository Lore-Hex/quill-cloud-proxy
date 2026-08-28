package imagegen

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	_ "golang.org/x/image/webp"
)

const (
	maxProviderResponseBytes = 160 << 20
	maxProviderErrorBytes    = 64 << 10
	maxGeneratedImageBytes   = 32 << 20
	maxGeneratedDimension    = 12_288
	maxGeneratedPixels       = 19_000_000
)

const bflGenerationTimeout = 5 * time.Minute
const kreaGenerationTimeout = 5 * time.Minute
const riverflowGenerationTimeout = 5 * time.Minute

const (
	bflInitialPollDelay = 500 * time.Millisecond
	bflMaxPollDelay     = 8 * time.Second
)

type ProviderKeys struct {
	OpenAI    string
	XAI       string
	Decart    string
	Recraft   string
	BFL       string
	Nscale    string
	Krea      string
	Riverflow string
}

type Registry struct {
	http *http.Client
	keys map[string]string
}

type GeneratedImage struct {
	B64       string
	MediaType string
	Width     int
	Height    int
}

type Usage struct {
	InputTokens  int
	OutputTokens int
	TotalTokens  int
}

type Result struct {
	Created int64
	Images  []GeneratedImage
	Usage   Usage
}

type ProviderError struct {
	StatusCode int
	Message    string
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("image provider returned HTTP %d: %s", e.StatusCode, e.Message)
}

func NewRegistry(keys ProviderKeys, client *http.Client) *Registry {
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	clone.Jar = nil
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if clone.Timeout == 0 {
		clone.Timeout = 10 * time.Minute
	}
	return &Registry{
		http: &clone,
		keys: map[string]string{
			"openai": keys.OpenAI, "grok": keys.XAI, "decart": keys.Decart,
			"recraft": keys.Recraft, "bfl": keys.BFL, "nscale": keys.Nscale,
			"krea":      keys.Krea,
			"riverflow": keys.Riverflow,
		},
	}
}

func (r *Registry) Enabled(provider string) bool {
	return r != nil && r.http != nil && strings.TrimSpace(r.keys[provider]) != ""
}

func (r *Registry) Generate(
	ctx context.Context,
	resolved *ResolvedRequest,
	providerAPIKey string,
	idempotencyKey string,
) (*Result, error) {
	if r == nil || resolved == nil {
		return nil, fmt.Errorf("image provider registry is unavailable")
	}
	if resolved.Spec.Pricing == PricingGeminiTokens {
		return nil, fmt.Errorf("gemini image generation uses the multimodal provider path")
	}
	key := strings.TrimSpace(providerAPIKey)
	if key == "" {
		key = strings.TrimSpace(r.keys[resolved.Spec.Provider])
	}
	if key == "" {
		return nil, fmt.Errorf("image provider key is unavailable")
	}
	if resolved.Spec.Provider == "bfl" {
		return r.generateBFL(ctx, resolved, key, idempotencyKey)
	}
	if resolved.Spec.Provider == "decart" {
		return r.generateDecart(ctx, resolved, key, idempotencyKey)
	}
	if resolved.Spec.Provider == "krea" {
		return r.generateKrea(ctx, resolved, key, idempotencyKey)
	}
	if resolved.Spec.Provider == "riverflow" {
		return r.generateRiverflow(ctx, resolved, key, idempotencyKey)
	}
	endpoint, payload, err := nativeRequest(resolved)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode image provider request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create image provider request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call image provider: %w", err)
	}
	defer resp.Body.Close()
	responseLimit := maxProviderResponseBytes
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		responseLimit = maxProviderErrorBytes
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(responseLimit)+1))
	if readErr != nil {
		return nil, fmt.Errorf("read image provider response: %w", readErr)
	}
	if len(responseBody) > responseLimit {
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, &ProviderError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
		}
		return nil, fmt.Errorf("image provider response exceeds the output limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, decodeProviderError(resp.StatusCode, responseBody)
	}
	var upstream struct {
		Created int64 `json:"created"`
		Data    []struct {
			B64JSON string `json:"b64_json"`
		} `json:"data"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
			TotalTokens  int `json:"total_tokens"`
		} `json:"usage"`
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	if err := decoder.Decode(&upstream); err != nil {
		return nil, fmt.Errorf("image provider returned invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("image provider returned invalid JSON")
	}
	if upstream.Usage.InputTokens < 0 || upstream.Usage.OutputTokens < 0 ||
		upstream.Usage.TotalTokens < 0 ||
		(upstream.Usage.TotalTokens > 0 &&
			upstream.Usage.TotalTokens < upstream.Usage.InputTokens+upstream.Usage.OutputTokens) {
		return nil, fmt.Errorf("image provider returned invalid usage")
	}
	if len(upstream.Data) == 0 || len(upstream.Data) > resolved.N {
		return nil, fmt.Errorf("image provider returned an invalid image count")
	}
	images := make([]GeneratedImage, 0, len(upstream.Data))
	for _, item := range upstream.Data {
		generated, err := ValidateImage(item.B64JSON, resolved.Format)
		if err != nil {
			return nil, err
		}
		if err := validateOutputShape(resolved, generated); err != nil {
			return nil, err
		}
		images = append(images, *generated)
	}
	created := upstream.Created
	if created <= 0 {
		created = time.Now().Unix()
	}
	total := upstream.Usage.TotalTokens
	if total == 0 {
		total = upstream.Usage.InputTokens + upstream.Usage.OutputTokens
	}
	return &Result{
		Created: created,
		Images:  images,
		Usage: Usage{
			InputTokens: upstream.Usage.InputTokens, OutputTokens: upstream.Usage.OutputTokens,
			TotalTokens: total,
		},
	}, nil
}

func nativeRequest(resolved *ResolvedRequest) (string, map[string]any, error) {
	base := map[string]any{
		"model": resolved.Spec.UpstreamID, "prompt": resolved.Request.Prompt,
		"n": resolved.N, "response_format": "b64_json",
	}
	switch resolved.Spec.Provider {
	case "openai":
		if resolved.AspectRatio != "" && resolved.AspectRatio != "auto" {
			size, ok := resolved.Spec.NativeSizes[resolved.AspectRatio]
			if !ok {
				return "", nil, fmt.Errorf("unsupported OpenAI image aspect ratio %q", resolved.AspectRatio)
			}
			base["size"] = size
		}
		if resolved.Quality != "" && resolved.Quality != "auto" {
			base["quality"] = resolved.Quality
		}
		if resolved.Background != "" && resolved.Background != "auto" {
			base["background"] = resolved.Background
		}
		if resolved.Format != "" {
			base["output_format"] = resolved.Format
		}
		// OpenAI documents compression as meaningful only for JPEG and WebP.
		// Keep the normalized field accepted for PNG, but do not forward a knob
		// that the selected native format cannot honor.
		if resolved.Request.OutputCompression != nil &&
			(resolved.Format == "jpeg" || resolved.Format == "webp") {
			base["output_compression"] = *resolved.Request.OutputCompression
		}
		for key, value := range resolved.PassthroughOptions() {
			base[key] = value
		}
		return "https://api.openai.com/v1/images/generations", base, nil
	case "grok":
		if resolved.Resolution != "" {
			base["resolution"] = strings.ToLower(resolved.Resolution)
		}
		if resolved.AspectRatio != "" {
			base["aspect_ratio"] = resolved.AspectRatio
		}
		if resolved.Quality != "" {
			base["quality"] = resolved.Quality
		}
		return "https://api.x.ai/v1/images/generations", base, nil
	case "recraft":
		size := resolved.Spec.NativeSizes[resolved.AspectRatio]
		if size == "" {
			return "", nil, fmt.Errorf("recraft model has no native size for %q", resolved.AspectRatio)
		}
		base["size"] = size
		return "https://external.api.recraft.ai/v1/images/generations", base, nil
	case "nscale":
		size := resolved.Spec.NativeSizes[resolved.AspectRatio]
		if size == "" {
			return "", nil, fmt.Errorf("Nscale model has no native size for %q", resolved.AspectRatio)
		}
		// Nscale does not accept response_format and documents b64_json as the
		// only successful response shape for this endpoint.
		delete(base, "response_format")
		base["size"] = size
		return "https://inference.api.nscale.com/v1/images/generations", base, nil
	default:
		return "", nil, fmt.Errorf("unsupported native image provider %q", resolved.Spec.Provider)
	}
}

func (r *Registry) generateBFL(
	ctx context.Context,
	resolved *ResolvedRequest,
	key, idempotencyKey string,
) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, bflGenerationTimeout)
	defer cancel()
	payload := map[string]any{
		"prompt": resolved.Request.Prompt, "width": 1024, "height": 1024,
		"output_format": "jpeg",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode BFL request: %w", err)
	}
	endpoint := "https://api.bfl.ai/v1/" + url.PathEscape(resolved.Spec.UpstreamID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create BFL request: %w", err)
	}
	req.Header.Set("x-key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	responseBody, status, err := r.doLimited(req, maxProviderErrorBytes)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, decodeProviderError(status, responseBody)
	}
	var submitted struct {
		ID         string `json:"id"`
		PollingURL string `json:"polling_url"`
	}
	if err := decodeExactJSON(responseBody, &submitted); err != nil || strings.TrimSpace(submitted.ID) == "" {
		return nil, fmt.Errorf("BFL returned an invalid job response")
	}
	pollURL, err := validateBFLPollingURL(submitted.PollingURL, submitted.ID)
	if err != nil {
		return nil, err
	}

	pollDelay := bflInitialPollDelay
	for {
		if err := waitForImagePoll(ctx, pollDelay); err != nil {
			return nil, err
		}
		pollReq, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
		if requestErr != nil {
			return nil, fmt.Errorf("create BFL poll request: %w", requestErr)
		}
		pollReq.Header.Set("x-key", key)
		pollReq.Header.Set("Accept", "application/json")
		pollBody, pollStatus, pollErr := r.doLimited(pollReq, maxProviderErrorBytes)
		if pollErr != nil {
			pollDelay = nextImagePollDelay(pollDelay)
			continue
		}
		if pollStatus < 200 || pollStatus > 299 {
			if pollStatus == http.StatusTooManyRequests || pollStatus >= 500 {
				pollDelay = nextImagePollDelay(pollDelay)
				continue
			}
			return nil, decodeProviderError(pollStatus, pollBody)
		}
		var poll struct {
			Status string `json:"status"`
			Result struct {
				Sample string `json:"sample"`
			} `json:"result"`
		}
		if err := decodeExactJSON(pollBody, &poll); err != nil {
			return nil, fmt.Errorf("BFL returned an invalid poll response")
		}
		switch strings.ToLower(strings.TrimSpace(poll.Status)) {
		case "ready":
			return r.downloadBFLResult(ctx, poll.Result.Sample, resolved)
		case "error", "failed", "request moderated", "content moderated":
			return nil, &ProviderError{StatusCode: http.StatusBadGateway, Message: "BFL generation failed"}
		case "pending", "processing", "task not started":
			pollDelay = nextImagePollDelay(pollDelay)
			continue
		default:
			return nil, fmt.Errorf("BFL returned an unknown job status")
		}
	}
}

func waitForImagePoll(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextImagePollDelay(current time.Duration) time.Duration {
	if current >= bflMaxPollDelay/2 {
		return bflMaxPollDelay
	}
	return current * 2
}

func validateBFLPollingURL(rawURL, jobID string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" ||
		parsed.Port() != "" || parsed.Fragment != "" ||
		!(parsed.Hostname() == "bfl.ai" || strings.HasSuffix(parsed.Hostname(), ".bfl.ai")) ||
		parsed.EscapedPath() != "/v1/get_result" {
		return "", fmt.Errorf("BFL returned an untrusted polling URL")
	}
	query := parsed.Query()
	ids, ok := query["id"]
	if !ok || len(query) != 1 || len(ids) != 1 || ids[0] != strings.TrimSpace(jobID) {
		return "", fmt.Errorf("BFL returned a polling URL for the wrong job")
	}
	return parsed.String(), nil
}

func (r *Registry) downloadBFLResult(ctx context.Context, rawURL string, resolved *ResolvedRequest) (*Result, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" ||
		parsed.Port() != "" || parsed.Fragment != "" ||
		!(parsed.Hostname() == "bfl.ai" || strings.HasSuffix(parsed.Hostname(), ".bfl.ai")) {
		return nil, fmt.Errorf("BFL returned an untrusted result URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create BFL result request: %w", err)
	}
	body, status, err := r.doLimited(req, maxGeneratedImageBytes)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, &ProviderError{StatusCode: status, Message: http.StatusText(status)}
	}
	generated, err := ValidateImage(base64.StdEncoding.EncodeToString(body), resolved.Format)
	if err != nil {
		return nil, err
	}
	if err := validateOutputShape(resolved, generated); err != nil {
		return nil, err
	}
	return &Result{Created: time.Now().Unix(), Images: []GeneratedImage{*generated}}, nil
}

func (r *Registry) generateDecart(
	ctx context.Context,
	resolved *ResolvedRequest,
	key, idempotencyKey string,
) (*Result, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for index, reference := range resolved.Request.InputReferences {
		mediaType, imageBytes, err := llm.LoadNormalizedImage(ctx, reference.ImageURL.URL)
		if err != nil {
			return nil, err
		}
		field := "data"
		if index == 1 {
			field = "reference_image"
		}
		extension := map[string]string{"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}[mediaType]
		part, err := writer.CreateFormFile(field, field+extension)
		if err != nil {
			return nil, fmt.Errorf("create Decart image field: %w", err)
		}
		if _, err := part.Write(imageBytes); err != nil {
			return nil, fmt.Errorf("write Decart image field: %w", err)
		}
	}
	if err := writer.WriteField("prompt", resolved.Request.Prompt); err != nil {
		return nil, fmt.Errorf("write Decart prompt: %w", err)
	}
	if err := writer.WriteField("resolution", resolved.Resolution); err != nil {
		return nil, fmt.Errorf("write Decart resolution: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish Decart request: %w", err)
	}
	endpoint := "https://api.decart.ai/v1/generate/" + url.PathEscape(resolved.Spec.UpstreamID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return nil, fmt.Errorf("create Decart request: %w", err)
	}
	req.Header.Set("X-API-KEY", key)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	responseBody, status, err := r.doLimited(req, maxGeneratedImageBytes)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, decodeProviderError(status, responseBody)
	}
	generated, err := ValidateImage(base64.StdEncoding.EncodeToString(responseBody), "")
	if err != nil {
		return nil, err
	}
	if err := validateOutputShape(resolved, generated); err != nil {
		return nil, err
	}
	return &Result{Created: time.Now().Unix(), Images: []GeneratedImage{*generated}}, nil
}

type kreaJob struct {
	JobID  string          `json:"job_id"`
	Status string          `json:"status"`
	Result json.RawMessage `json:"result"`
	Error  struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (r *Registry) generateKrea(
	ctx context.Context,
	resolved *ResolvedRequest,
	key, idempotencyKey string,
) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, kreaGenerationTimeout)
	defer cancel()
	payload := map[string]any{
		"prompt":       resolved.Request.Prompt,
		"aspect_ratio": resolved.AspectRatio,
		"resolution":   resolved.Resolution,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode Krea request: %w", err)
	}
	endpoint := "https://api.krea.ai/generate/image/" + resolved.Spec.UpstreamID
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create Krea request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	responseBody, status, err := r.doLimited(req, maxProviderErrorBytes)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, decodeProviderError(status, responseBody)
	}
	var job kreaJob
	if err := decodeExactJSON(responseBody, &job); err != nil || strings.TrimSpace(job.JobID) == "" {
		return nil, fmt.Errorf("Krea returned an invalid job response")
	}

	pollDelay := bflInitialPollDelay
	for {
		if err := waitForImagePoll(ctx, pollDelay); err != nil {
			return nil, err
		}
		pollURL := "https://api.krea.ai/jobs/" + url.PathEscape(strings.TrimSpace(job.JobID))
		pollReq, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
		if requestErr != nil {
			return nil, fmt.Errorf("create Krea poll request: %w", requestErr)
		}
		pollReq.Header.Set("Authorization", "Bearer "+key)
		pollReq.Header.Set("Accept", "application/json")
		pollBody, pollStatus, pollErr := r.doLimited(pollReq, maxProviderErrorBytes)
		if pollErr != nil {
			pollDelay = nextImagePollDelay(pollDelay)
			continue
		}
		if pollStatus < 200 || pollStatus > 299 {
			if pollStatus == http.StatusTooManyRequests || pollStatus >= 500 {
				pollDelay = nextImagePollDelay(pollDelay)
				continue
			}
			return nil, decodeProviderError(pollStatus, pollBody)
		}
		job = kreaJob{}
		if err := decodeExactJSON(pollBody, &job); err != nil {
			return nil, fmt.Errorf("Krea returned an invalid poll response")
		}
		switch strings.ToLower(strings.TrimSpace(job.Status)) {
		case "completed":
			resultURL, urlErr := kreaResultURL(job.Result)
			if urlErr != nil {
				return nil, urlErr
			}
			mediaType, imageBytes, loadErr := llm.LoadNormalizedImage(ctx, resultURL)
			if loadErr != nil {
				return nil, fmt.Errorf("load Krea result: %w", loadErr)
			}
			generated, validateErr := ValidateImage(
				base64.StdEncoding.EncodeToString(imageBytes),
				strings.TrimPrefix(mediaType, "image/"),
			)
			if validateErr != nil {
				return nil, validateErr
			}
			if shapeErr := validateOutputShape(resolved, generated); shapeErr != nil {
				return nil, shapeErr
			}
			return &Result{Created: time.Now().Unix(), Images: []GeneratedImage{*generated}}, nil
		case "failed", "cancelled":
			message := strings.TrimSpace(job.Error.Message)
			if message == "" {
				message = "Krea generation failed"
			}
			return nil, &ProviderError{StatusCode: http.StatusBadGateway, Message: message}
		case "backlogged", "queued", "scheduled", "processing", "sampling", "intermediate-complete":
			pollDelay = nextImagePollDelay(pollDelay)
			continue
		default:
			return nil, fmt.Errorf("Krea returned an unknown job status")
		}
	}
}

func kreaResultURL(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("Krea completed without an image URL")
	}
	var result struct {
		URLs json.RawMessage `json:"urls"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || len(result.URLs) == 0 {
		return "", fmt.Errorf("Krea returned an invalid result")
	}
	var stringsList []string
	if json.Unmarshal(result.URLs, &stringsList) == nil {
		for _, candidate := range stringsList {
			if strings.TrimSpace(candidate) != "" {
				return candidate, nil
			}
		}
	}
	var typed []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if json.Unmarshal(result.URLs, &typed) == nil {
		for _, wanted := range []string{"model", "preview"} {
			for _, candidate := range typed {
				if candidate.Type == wanted && strings.TrimSpace(candidate.URL) != "" {
					return candidate.URL, nil
				}
			}
		}
	}
	var mapped map[string]string
	if json.Unmarshal(result.URLs, &mapped) == nil {
		if candidate := strings.TrimSpace(mapped["model"]); candidate != "" {
			return candidate, nil
		}
		keys := make([]string, 0, len(mapped))
		for key := range mapped {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if candidate := strings.TrimSpace(mapped[key]); candidate != "" {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("Krea completed without an image URL")
}

type riverflowPollResponse struct {
	Data struct {
		Job struct {
			ID               string `json:"id"`
			Status           string `json:"status"`
			LastErrorMessage string `json:"lastErrorMessage"`
			Cost             struct {
				Currency string      `json:"currency"`
				TaskCost json.Number `json:"taskCost"`
			} `json:"cost"`
		} `json:"job"`
		Artifacts []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
			URL    string `json:"url"`
		} `json:"artifacts"`
	} `json:"data"`
}

func (r *Registry) generateRiverflow(
	ctx context.Context,
	resolved *ResolvedRequest,
	key, idempotencyKey string,
) (*Result, error) {
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		return nil, fmt.Errorf("Riverflow requires an idempotency key")
	}
	ctx, cancel := context.WithTimeout(ctx, riverflowGenerationTimeout)
	defer cancel()
	payload := map[string]any{
		"model": resolved.Spec.UpstreamID, "instruction": resolved.Request.Prompt,
		"idempotencyKey": idempotencyKey, "resolution": resolved.Resolution,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode Riverflow request: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, "https://design-api.sourceful.com/v2/generations/t2i", bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create Riverflow request: %w", err)
	}
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	responseBody, status, err := r.doLimited(req, maxProviderErrorBytes)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, decodeProviderError(status, responseBody)
	}
	var submitted struct {
		Data struct {
			JobID  string `json:"jobId"`
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := decodeExactJSON(responseBody, &submitted); err != nil || strings.TrimSpace(submitted.Data.JobID) == "" {
		return nil, fmt.Errorf("Riverflow returned an invalid job response")
	}

	pollDelay := bflInitialPollDelay
	for {
		if err := waitForImagePoll(ctx, pollDelay); err != nil {
			return nil, err
		}
		pollURL := "https://design-api.sourceful.com/v2/generations/" + url.PathEscape(submitted.Data.JobID)
		pollReq, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
		if requestErr != nil {
			return nil, fmt.Errorf("create Riverflow poll request: %w", requestErr)
		}
		pollReq.Header.Set("X-API-Key", key)
		pollReq.Header.Set("Accept", "application/json")
		pollBody, pollStatus, pollErr := r.doLimited(pollReq, maxProviderErrorBytes)
		if pollErr != nil {
			pollDelay = nextImagePollDelay(pollDelay)
			continue
		}
		if pollStatus < 200 || pollStatus > 299 {
			if pollStatus == http.StatusTooManyRequests || pollStatus >= 500 {
				pollDelay = nextImagePollDelay(pollDelay)
				continue
			}
			return nil, decodeProviderError(pollStatus, pollBody)
		}
		var polled riverflowPollResponse
		if err := decodeExactJSON(pollBody, &polled); err != nil {
			return nil, fmt.Errorf("Riverflow returned an invalid poll response")
		}
		if strings.TrimSpace(polled.Data.Job.ID) != submitted.Data.JobID {
			return nil, fmt.Errorf("Riverflow returned a mismatched job response")
		}
		switch strings.ToLower(strings.TrimSpace(polled.Data.Job.Status)) {
		case "completed", "succeeded", "success":
			receipt, receiptErr := exactUSDMicrodollars(polled.Data.Job.Cost.TaskCost)
			if receiptErr != nil || !strings.EqualFold(polled.Data.Job.Cost.Currency, "USD") ||
				receipt != resolved.FixedProviderCostMicrodollars() {
				return nil, fmt.Errorf("Riverflow receipt does not match the authorized price")
			}
			for _, artifact := range polled.Data.Artifacts {
				if !strings.EqualFold(artifact.Type, "image") ||
					!strings.EqualFold(artifact.Status, "ready") || strings.TrimSpace(artifact.URL) == "" {
					continue
				}
				_, imageBytes, loadErr := llm.LoadNormalizedImage(ctx, artifact.URL)
				if loadErr != nil {
					return nil, fmt.Errorf("load Riverflow result: %w", loadErr)
				}
				generated, validateErr := ValidateImage(
					base64.StdEncoding.EncodeToString(imageBytes), resolved.Format,
				)
				if validateErr != nil {
					return nil, validateErr
				}
				if shapeErr := validateOutputShape(resolved, generated); shapeErr != nil {
					return nil, shapeErr
				}
				return &Result{Created: time.Now().Unix(), Images: []GeneratedImage{*generated}}, nil
			}
			return nil, fmt.Errorf("Riverflow completed without a ready image")
		case "failed", "cancelled", "canceled", "error":
			message := strings.TrimSpace(polled.Data.Job.LastErrorMessage)
			if message == "" {
				message = "Riverflow generation failed"
			}
			return nil, &ProviderError{StatusCode: http.StatusBadGateway, Message: message}
		case "created", "queued", "pending", "processing", "running", "generating":
			pollDelay = nextImagePollDelay(pollDelay)
			continue
		default:
			return nil, fmt.Errorf("Riverflow returned an unknown job status")
		}
	}
}

func exactUSDMicrodollars(value json.Number) (int, error) {
	raw := strings.TrimSpace(value.String())
	if raw == "" || len(raw) > 24 || strings.ContainsAny(raw, "+-eE/") {
		return 0, fmt.Errorf("invalid USD amount")
	}
	parts := strings.Split(raw, ".")
	if len(parts) > 2 || parts[0] == "" {
		return 0, fmt.Errorf("invalid USD amount")
	}
	whole, err := strconv.ParseUint(parts[0], 10, 63)
	if err != nil || whole > uint64(math.MaxInt)/1_000_000 {
		return 0, fmt.Errorf("invalid USD amount")
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
	}
	if len(fraction) > 6 {
		return 0, fmt.Errorf("USD amount is not an exact microdollar value")
	}
	for len(fraction) < 6 {
		fraction += "0"
	}
	fractionalMicrodollars := uint64(0)
	if fraction != "" {
		fractionalMicrodollars, err = strconv.ParseUint(fraction, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid USD amount")
		}
	}
	microdollars := whole*1_000_000 + fractionalMicrodollars
	if microdollars == 0 || microdollars > uint64(math.MaxInt) {
		return 0, fmt.Errorf("USD amount is outside the supported range")
	}
	return int(microdollars), nil
}

func (r *Registry) doLimited(req *http.Request, limit int) ([]byte, int, error) {
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("call image provider: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read image provider response: %w", err)
	}
	if len(body) > limit {
		return nil, resp.StatusCode, fmt.Errorf("image provider response exceeds the output limit")
	}
	return body, resp.StatusCode, nil
}

func decodeExactJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func validateOutputShape(resolved *ResolvedRequest, generated *GeneratedImage) error {
	switch resolved.Spec.Provider {
	case "openai", "recraft", "riverflow":
		if resolved.AspectRatio == "" || resolved.AspectRatio == "auto" {
			return nil
		}
		size, ok := resolved.Spec.NativeSizes[resolved.AspectRatio]
		if !ok {
			return fmt.Errorf("image provider returned dimensions outside the request")
		}
		var width, height int
		if _, err := fmt.Sscanf(size, "%dx%d", &width, &height); err != nil ||
			generated.Width != width || generated.Height != height {
			return fmt.Errorf("image provider returned dimensions outside the request")
		}
	case "grok":
		targetPixels := 1_048_576
		if resolved.Resolution == "2K" {
			targetPixels = 4_194_304
		}
		pixels := generated.Width * generated.Height
		if pixels < targetPixels*9/10 || pixels > targetPixels*11/10 {
			return fmt.Errorf("image provider returned dimensions outside the request")
		}
		if resolved.AspectRatio == "" || resolved.AspectRatio == "auto" {
			return nil
		}
		parts := strings.Split(resolved.AspectRatio, ":")
		if len(parts) != 2 {
			return fmt.Errorf("image provider returned dimensions outside the request")
		}
		wantWidth, widthErr := strconv.ParseFloat(parts[0], 64)
		wantHeight, heightErr := strconv.ParseFloat(parts[1], 64)
		if widthErr != nil || heightErr != nil || wantWidth <= 0 || wantHeight <= 0 {
			return fmt.Errorf("image provider returned dimensions outside the request")
		}
		wantRatio := wantWidth / wantHeight
		gotRatio := float64(generated.Width) / float64(generated.Height)
		if math.Abs(gotRatio-wantRatio)/wantRatio > 0.02 {
			return fmt.Errorf("image provider returned dimensions outside the request")
		}
	case "bfl", "nscale", "krea":
		if generated.Width != 1024 || generated.Height != 1024 {
			return fmt.Errorf("image provider returned dimensions outside the request")
		}
	case "decart":
		longEdge := max(generated.Width, generated.Height)
		minimum, maximum := 400, 540
		if resolved.Resolution == "720p" {
			minimum, maximum = 600, 810
		}
		if longEdge < minimum || longEdge > maximum {
			return fmt.Errorf("image provider returned dimensions outside the request")
		}
	}
	return nil
}

func decodeProviderError(status int, body []byte) error {
	message := http.StatusText(status)
	var decoded struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &decoded) == nil && strings.TrimSpace(decoded.Error.Message) != "" {
		message = strings.TrimSpace(decoded.Error.Message)
	}
	if len(message) > 512 {
		message = message[:512]
	}
	message = strings.NewReplacer("\r", " ", "\n", " ").Replace(message)
	return &ProviderError{StatusCode: status, Message: message}
}

func ValidateImage(encoded, requestedFormat string) (*GeneratedImage, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maxGeneratedImageBytes) {
		return nil, fmt.Errorf("image provider returned invalid image base64")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maxGeneratedImageBytes {
		return nil, fmt.Errorf("image provider returned invalid image base64")
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || config.Width <= 0 || config.Height <= 0 {
		return nil, fmt.Errorf("image provider returned invalid image bytes")
	}
	if config.Width > maxGeneratedDimension || config.Height > maxGeneratedDimension ||
		config.Width > maxGeneratedPixels/config.Height {
		return nil, fmt.Errorf("image provider image dimensions exceed the output limit")
	}
	if _, decodedFormat, err := image.Decode(bytes.NewReader(raw)); err != nil || decodedFormat != format {
		return nil, fmt.Errorf("image provider returned invalid image bytes")
	}
	mediaTypes := map[string]string{"jpeg": "image/jpeg", "png": "image/png", "webp": "image/webp"}
	mediaType := mediaTypes[format]
	if mediaType == "" {
		return nil, fmt.Errorf("image provider returned an unsupported image format")
	}
	want := strings.ToLower(strings.TrimSpace(requestedFormat))
	if want == "jpg" {
		want = "jpeg"
	}
	if want != "" && want != format {
		return nil, fmt.Errorf("image provider output format does not match the request")
	}
	return &GeneratedImage{
		B64: encoded, MediaType: mediaType, Width: config.Width, Height: config.Height,
	}, nil
}
