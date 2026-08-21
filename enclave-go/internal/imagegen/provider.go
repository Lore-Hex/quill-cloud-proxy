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
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "golang.org/x/image/webp"
)

const (
	maxProviderResponseBytes = 160 << 20
	maxProviderErrorBytes    = 64 << 10
	maxGeneratedImageBytes   = 32 << 20
	maxGeneratedDimension    = 12_288
	maxGeneratedPixels       = 19_000_000
)

type ProviderKeys struct {
	OpenAI string
	XAI    string
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
		keys: map[string]string{"openai": keys.OpenAI, "grok": keys.XAI},
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
	default:
		return "", nil, fmt.Errorf("unsupported native image provider %q", resolved.Spec.Provider)
	}
}

func validateOutputShape(resolved *ResolvedRequest, generated *GeneratedImage) error {
	switch resolved.Spec.Provider {
	case "openai":
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
