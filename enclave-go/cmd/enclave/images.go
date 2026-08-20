package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/byokcache"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	maxImagePromptBytes        = 512 << 10
	maxGeneratedImageBytes     = 32 << 20
	maxGeneratedImageDimension = 12_288
	maxGeneratedImagePixels    = 19_000_000
)

var imageOutputTokensByResolution = map[string]int{
	"512": 747,
	"1K":  1120,
	"2K":  1680,
	"4K":  2520,
}

var imageAspectRatios = map[string]struct{}{
	"1:1": {}, "1:4": {}, "1:8": {}, "2:3": {}, "3:2": {}, "3:4": {},
	"4:1": {}, "4:3": {}, "4:5": {}, "5:4": {}, "8:1": {}, "9:16": {},
	"16:9": {}, "21:9": {},
}

var imageNativeSizes = map[string]struct{ resolution, aspectRatio string }{
	"512x512": {"512", "1:1"}, "256x1024": {"512", "1:4"}, "192x1536": {"512", "1:8"},
	"424x632": {"512", "2:3"}, "632x424": {"512", "3:2"}, "448x600": {"512", "3:4"},
	"1024x256": {"512", "4:1"}, "600x448": {"512", "4:3"}, "464x576": {"512", "4:5"},
	"576x464": {"512", "5:4"}, "1536x192": {"512", "8:1"}, "384x688": {"512", "9:16"},
	"688x384": {"512", "16:9"}, "792x168": {"512", "21:9"},
	"1024x1024": {"1K", "1:1"}, "512x2048": {"1K", "1:4"}, "384x3072": {"1K", "1:8"},
	"848x1264": {"1K", "2:3"}, "1264x848": {"1K", "3:2"}, "896x1200": {"1K", "3:4"},
	"2048x512": {"1K", "4:1"}, "1200x896": {"1K", "4:3"}, "928x1152": {"1K", "4:5"},
	"1152x928": {"1K", "5:4"}, "3072x384": {"1K", "8:1"}, "768x1376": {"1K", "9:16"},
	"1376x768": {"1K", "16:9"}, "1584x672": {"1K", "21:9"},
	"2048x2048": {"2K", "1:1"}, "1024x4096": {"2K", "1:4"}, "768x6144": {"2K", "1:8"},
	"1696x2528": {"2K", "2:3"}, "2528x1696": {"2K", "3:2"}, "1792x2400": {"2K", "3:4"},
	"4096x1024": {"2K", "4:1"}, "2400x1792": {"2K", "4:3"}, "1856x2304": {"2K", "4:5"},
	"2304x1856": {"2K", "5:4"}, "6144x768": {"2K", "8:1"}, "1536x2752": {"2K", "9:16"},
	"2752x1536": {"2K", "16:9"}, "3168x1344": {"2K", "21:9"},
	"4096x4096": {"4K", "1:1"}, "2048x8192": {"4K", "1:4"}, "1536x12288": {"4K", "1:8"},
	"3392x5056": {"4K", "2:3"}, "5056x3392": {"4K", "3:2"}, "3584x4800": {"4K", "3:4"},
	"8192x2048": {"4K", "4:1"}, "4800x3584": {"4K", "4:3"}, "3712x4608": {"4K", "4:5"},
	"4608x3712": {"4K", "5:4"}, "12288x1536": {"4K", "8:1"}, "3072x5504": {"4K", "9:16"},
	"5504x3072": {"4K", "16:9"}, "6336x2688": {"4K", "21:9"},
}

type imageReference struct {
	Type     string `json:"type"`
	ImageURL struct {
		URL string `json:"url"`
	} `json:"image_url"`
}

type imageGenerationRequest struct {
	Model             string                 `json:"model"`
	Prompt            string                 `json:"prompt"`
	N                 *int                   `json:"n,omitempty"`
	Resolution        string                 `json:"resolution,omitempty"`
	AspectRatio       string                 `json:"aspect_ratio,omitempty"`
	Size              string                 `json:"size,omitempty"`
	Quality           string                 `json:"quality,omitempty"`
	OutputFormat      string                 `json:"output_format,omitempty"`
	Background        string                 `json:"background,omitempty"`
	OutputCompression *int                   `json:"output_compression,omitempty"`
	Seed              *int                   `json:"seed,omitempty"`
	Stream            bool                   `json:"stream,omitempty"`
	InputReferences   []imageReference       `json:"input_references,omitempty"`
	Provider          *types.ProviderRouting `json:"provider,omitempty"`
	Metadata          map[string]any         `json:"metadata,omitempty"`
	Trace             map[string]any         `json:"trace,omitempty"`
	User              string                 `json:"user,omitempty"`
	SessionID         string                 `json:"session_id,omitempty"`
	Tags              *types.RequestTags     `json:"tags,omitempty"`
}

type resolvedImageRequest struct {
	request     imageGenerationRequest
	resolution  string
	aspectRatio string
}

type imageRequestError struct {
	message string
	param   string
}

func (e *imageRequestError) Error() string { return e.message }

func parseImageGenerationRequest(raw []byte) (*resolvedImageRequest, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var req imageGenerationRequest
	if err := decoder.Decode(&req); err != nil {
		return nil, &imageRequestError{message: "invalid image request"}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, &imageRequestError{message: "invalid image request"}
	}
	req.Model = strings.TrimSpace(req.Model)
	if req.Model == "" {
		return nil, &imageRequestError{message: "model is required", param: "model"}
	}
	if strings.TrimSpace(req.Prompt) == "" {
		return nil, &imageRequestError{message: "prompt is required", param: "prompt"}
	}
	if len(req.Prompt) > maxImagePromptBytes {
		return nil, &imageRequestError{message: "prompt is too long", param: "prompt"}
	}
	if req.N != nil && *req.N != 1 {
		return nil, &imageRequestError{message: "this model supports n=1 only", param: "n"}
	}
	if len(req.InputReferences) > 14 {
		return nil, &imageRequestError{message: "input_references supports at most 14 images", param: "input_references"}
	}
	for i, reference := range req.InputReferences {
		if reference.Type != "image_url" || strings.TrimSpace(reference.ImageURL.URL) == "" {
			return nil, &imageRequestError{
				message: "each input reference must be an image_url with a non-empty url",
				param:   fmt.Sprintf("input_references[%d]", i),
			}
		}
	}
	if req.Provider != nil && len(req.Provider.Options) > 0 {
		return nil, &imageRequestError{message: "provider.options is not supported by the selected endpoint", param: "provider.options"}
	}
	for value, field := range map[string]string{
		req.Quality: "quality", req.Background: "background",
	} {
		if strings.TrimSpace(value) != "" {
			return nil, &imageRequestError{message: field + " is not supported by the selected endpoint", param: field}
		}
	}
	if req.OutputCompression != nil {
		return nil, &imageRequestError{message: "output_compression is not supported by the selected endpoint", param: "output_compression"}
	}
	if req.Seed != nil {
		return nil, &imageRequestError{message: "seed is not supported by the selected endpoint", param: "seed"}
	}
	if strings.TrimSpace(req.OutputFormat) != "" {
		return nil, &imageRequestError{message: "output_format is not supported by the selected endpoint", param: "output_format"}
	}

	resolution := normalizeImageResolution(req.Resolution)
	if req.Resolution != "" && resolution == "" {
		return nil, &imageRequestError{message: "resolution must be one of 512, 1K, 2K, or 4K", param: "resolution"}
	}
	aspectRatio := strings.TrimSpace(req.AspectRatio)
	if aspectRatio != "" {
		if _, ok := imageAspectRatios[aspectRatio]; !ok {
			return nil, &imageRequestError{message: "unsupported aspect_ratio", param: "aspect_ratio"}
		}
	}
	if size := strings.TrimSpace(req.Size); size != "" {
		if tier := normalizeImageResolution(size); tier != "" {
			if resolution != "" && resolution != tier {
				return nil, &imageRequestError{message: "size conflicts with resolution", param: "size"}
			}
			resolution = tier
		} else if native, ok := imageNativeSizes[strings.ToLower(size)]; ok {
			if resolution != "" && resolution != native.resolution {
				return nil, &imageRequestError{message: "size conflicts with resolution", param: "size"}
			}
			if aspectRatio != "" && aspectRatio != native.aspectRatio {
				return nil, &imageRequestError{message: "size conflicts with aspect_ratio", param: "size"}
			}
			resolution, aspectRatio = native.resolution, native.aspectRatio
		} else {
			return nil, &imageRequestError{message: "size is not a native size for this model", param: "size"}
		}
	}
	if resolution == "" {
		resolution = "1K"
	}
	if aspectRatio == "" {
		aspectRatio = "1:1"
	}
	return &resolvedImageRequest{request: req, resolution: resolution, aspectRatio: aspectRatio}, nil
}

func normalizeImageResolution(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "512":
		return "512"
	case "1K":
		return "1K"
	case "2K":
		return "2K"
	case "4K":
		return "4K"
	default:
		return ""
	}
}

type generatedImage struct {
	b64       string
	mediaType string
	width     int
	height    int
}

func parseGeneratedImage(text string) (*generatedImage, error) {
	value := strings.TrimSpace(text)
	header, encoded, ok := strings.Cut(value, ",")
	if !ok || !strings.HasPrefix(header, "data:image/") || !strings.HasSuffix(header, ";base64") || encoded == "" {
		return nil, fmt.Errorf("provider did not return exactly one complete image")
	}
	if len(encoded) > base64.StdEncoding.EncodedLen(maxGeneratedImageBytes) {
		return nil, fmt.Errorf("provider image exceeds the output limit")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maxGeneratedImageBytes {
		return nil, fmt.Errorf("provider returned invalid image base64")
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || config.Width <= 0 || config.Height <= 0 {
		return nil, fmt.Errorf("provider returned invalid image bytes")
	}
	if config.Width > maxGeneratedImageDimension || config.Height > maxGeneratedImageDimension ||
		config.Width > maxGeneratedImagePixels/config.Height {
		return nil, fmt.Errorf("provider image dimensions exceed the output limit")
	}
	mediaType := strings.TrimSuffix(strings.TrimPrefix(header, "data:"), ";base64")
	wantType := map[string]string{"png": "image/png", "jpeg": "image/jpeg"}[format]
	if wantType == "" || mediaType != wantType {
		return nil, fmt.Errorf("provider image media type does not match its bytes")
	}
	return &generatedImage{
		b64: encoded, mediaType: mediaType, width: config.Width, height: config.Height,
	}, nil
}

func expectedImageDimensions(resolution, aspectRatio string) (int, int, bool) {
	for size, native := range imageNativeSizes {
		if native.resolution != resolution || native.aspectRatio != aspectRatio {
			continue
		}
		var width, height int
		if _, err := fmt.Sscanf(size, "%dx%d", &width, &height); err == nil {
			return width, height, true
		}
	}
	return 0, 0, false
}

func imageRequestFingerprint(bearer string, req *imageGenerationRequest) string {
	canonical, err := json.Marshal(req)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(bearer))
	_, _ = mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

func imageChatRequest(resolved *resolvedImageRequest, idempotencyKey string, attribution requestAttributionHeaders) *types.OpenAIChatRequest {
	parts := make([]types.ChatContentPart, 0, 1+len(resolved.request.InputReferences))
	parts = append(parts, types.ChatContentPart{Type: "text", Text: resolved.request.Prompt})
	for _, reference := range resolved.request.InputReferences {
		parts = append(parts, types.ChatContentPart{
			Type:     "image_url",
			ImageURL: &types.ChatImageURL{URL: reference.ImageURL.URL, Detail: "original"},
		})
	}
	outputTokens := imageOutputTokensByResolution[resolved.resolution]
	req := &types.OpenAIChatRequest{
		Model:            resolved.request.Model,
		Messages:         []types.OpenAIChatMessage{{Role: "user", Content: parts}},
		Stream:           resolved.request.Stream,
		MaxTokens:        &outputTokens,
		Provider:         resolved.request.Provider,
		Metadata:         resolved.request.Metadata,
		Trace:            resolved.request.Trace,
		User:             resolved.request.User,
		SessionID:        resolved.request.SessionID,
		Tags:             types.CloneRequestTags(resolved.request.Tags),
		IdempotencyKey:   idempotencyKey,
		ImageGeneration:  true,
		ImageResolution:  resolved.resolution,
		ImageAspectRatio: resolved.aspectRatio,
	}
	applyAttributionHeaders(req, attribution)
	return req
}

func serveImages(
	ctx context.Context,
	conn io.Writer,
	br llm.Client,
	body []byte,
	trGateway *trustedrouter.Client,
	bearer string,
	secretCache *byokcache.Cache,
	idempotencyKey string,
	attribution requestAttributionHeaders,
	requestLogID string,
) {
	started := time.Now()
	resolved, err := parseImageGenerationRequest(body)
	if err != nil {
		var requestErr *imageRequestError
		if errors.As(err, &requestErr) {
			writeOpenAIError(conn, http.StatusBadRequest, requestErr.message, "invalid_request_error", "bad_request", requestErr.param)
			return
		}
		writeOpenAIError(conn, http.StatusBadRequest, "invalid image request", "invalid_request_error", "bad_request", "")
		return
	}
	if trGateway == nil || !trGateway.Enabled() {
		writeRetryableError(conn, http.StatusServiceUnavailable, "image generation is temporarily unavailable")
		return
	}
	req := imageChatRequest(resolved, idempotencyKey, attribution)
	req.RequestFingerprint = imageRequestFingerprint(bearer, &resolved.request)
	if err := validateOrObserveRequestMetadata(req, requestLogID); err != nil {
		writeOpenAIError(conn, 400, err.Error(), "invalid_request_error", "invalid_request_metadata", "")
		return
	}
	authorization, err := trGateway.AuthorizeWithRoute(ctx, bearer, req, "images")
	if err != nil {
		writeErrorWithSourceHeaders(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "gateway authorization failed"), "router", retryHeadersFromControlPlaneError(err))
		return
	}
	invokeOptions, err := invokeOptionsForAuthorization(ctx, secretCache, authorization)
	if err != nil || len(invokeOptions) == 0 {
		refundImageGeneration(ctx, trGateway, authorization, 502, "byok_secret_error", started, req.Metadata)
		writeProviderError(conn, 502, "image provider unavailable")
		return
	}
	if invokeOptions[0].Model != "" {
		req.Model = invokeOptions[0].Model
	} else if authorization.Model != "" {
		req.Model = authorization.Model
	}
	anthropicReq, err := adapter.ToAnthropic(req, req.Model)
	if err != nil {
		refundImageGeneration(ctx, trGateway, authorization, 400, "invalid_request", started, req.Metadata)
		writeOpenAIError(conn, 400, "invalid image request", "invalid_request_error", "bad_request", "")
		return
	}

	generationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	clientClosed := cancelUserModelOnDisconnect(generationCtx, cancel, conn)
	pr, pw := io.Pipe()
	selectedRoute := newSelectedRouteTracker()
	go invokeProviderStream(generationCtx, br, req, anthropicReq, pw, invokeOptions, true, authorization, selectedRoute, requestLogID, true, false)
	result, collectErr := adapter.CollectAnthropicTextStrict(pr)
	if collectErr != nil {
		cancel()
		status, message := upstreamErrorResponse(collectErr)
		if clientClosed.Load() {
			refundImageGeneration(ctx, trGateway, authorization, 499, "client_closed", started, req.Metadata)
			return
		}
		refundImageGeneration(ctx, trGateway, authorization, status, failureReason(collectErr), started, req.Metadata)
		fmt.Fprintf(os.Stderr, "enclave.images_failed model=%q err=%v\n", req.Model, collectErr)
		writeClassifiedOpenAIError(conn, status, message, collectErr)
		return
	}
	imageResult, err := parseGeneratedImage(result.Text)
	if err != nil {
		refundImageGeneration(ctx, trGateway, authorization, 502, "invalid_image_output", started, req.Metadata)
		fmt.Fprintf(os.Stderr, "enclave.images_invalid_output model=%q err=%v\n", req.Model, err)
		writeProviderError(conn, 502, "image generation failed")
		return
	}
	if imageResult.mediaType != "image/jpeg" {
		refundImageGeneration(ctx, trGateway, authorization, 502, "invalid_image_output", started, req.Metadata)
		fmt.Fprintf(os.Stderr, "enclave.images_wrong_format model=%q media_type=%q\n", req.Model, imageResult.mediaType)
		writeProviderError(conn, 502, "image generation failed")
		return
	}
	wantWidth, wantHeight, dimensionsKnown := expectedImageDimensions(resolved.resolution, resolved.aspectRatio)
	if !dimensionsKnown || imageResult.width != wantWidth || imageResult.height != wantHeight {
		refundImageGeneration(ctx, trGateway, authorization, 502, "invalid_image_dimensions", started, req.Metadata)
		fmt.Fprintf(
			os.Stderr,
			"enclave.images_invalid_dimensions model=%q width=%d height=%d\n",
			req.Model,
			imageResult.width,
			imageResult.height,
		)
		writeProviderError(conn, 502, "image generation failed")
		return
	}
	if clientClosed.Load() {
		refundImageGeneration(ctx, trGateway, authorization, 499, "client_closed", started, req.Metadata)
		return
	}
	inputTokens, providerOutputTokens, usageEstimated := realOrEstimatedTokens(
		result,
		trustedrouter.EstimateInputTokens(req),
		imageOutputTokensByResolution[resolved.resolution],
	)
	// The endpoint tariff is the published image-output rate. Gemini reports
	// thinking tokens in the same aggregate completion count even though those
	// tokens have a much lower provider price. Bill exactly the documented image
	// token tier; TrustedRouter absorbs any private reasoning overhead rather
	// than incorrectly charging it at the image rate. The public usage envelope
	// still reports the provider's complete output count.
	billedOutputTokens := imageOutputTokensByResolution[resolved.resolution]
	selectedModel := selectedRoute.Model(req.Model, authorization)
	selectedEndpoint := selectedRoute.Endpoint("", authorization)
	usage := trustedrouter.Usage{
		RequestID: newRequestID(), InputTokens: inputTokens, OutputTokens: billedOutputTokens,
		ElapsedSeconds: maxDurationSeconds(time.Since(started), 0.001), UsageEstimated: usageEstimated,
		FinishReason: result.FinishReason, Streamed: resolved.request.Stream, RouteType: "images",
		SelectedModel: selectedModel, SelectedEndpoint: selectedEndpoint,
		User: req.User, SessionID: req.SessionID, Trace: req.Trace, Metadata: req.Metadata,
	}
	applyUsageAttribution(&usage, req)
	settlement, err := trGateway.Settle(ctx, authorization, usage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.images_settle_failed model=%q err=%v\n", req.Model, err)
		writeSpentError(conn, 502, "settlement failed")
		return
	}
	created := time.Now().Unix()
	responseUsage := map[string]any{
		"prompt_tokens": inputTokens, "completion_tokens": providerOutputTokens,
		"total_tokens": inputTokens + providerOutputTokens, "cost": settlement.Cost,
	}
	if resolved.request.Stream {
		if err := writeResponseHead(conn, 200, "text/event-stream"); err != nil {
			return
		}
		chunked := newChunkedWriter(conn)
		payload, _ := json.Marshal(map[string]any{
			"type": "image_generation.completed", "b64_json": imageResult.b64,
			"media_type": imageResult.mediaType, "created": created, "usage": responseUsage,
		})
		_, _ = fmt.Fprintf(chunked, "data: %s\n\ndata: [DONE]\n\n", payload)
		_ = chunked.Close()
		return
	}
	payload, err := json.Marshal(map[string]any{
		"created": created,
		"data":    []map[string]any{{"b64_json": imageResult.b64, "media_type": imageResult.mediaType}},
		"usage":   responseUsage,
	})
	if err != nil {
		writeSpentError(conn, 500, "image response encoding failed")
		return
	}
	writeJSONResponse(conn, 200, payload)
}

func refundImageGeneration(
	ctx context.Context,
	client *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	status int,
	errorType string,
	started time.Time,
	metadata map[string]any,
) {
	if client == nil || authorization == nil {
		return
	}
	refundCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = client.Refund(refundCtx, authorization, status, errorType, time.Since(started).Seconds(), metadata)
}
