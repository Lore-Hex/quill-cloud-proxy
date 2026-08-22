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
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/imagegen"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	maxGeneratedImageBytes     = 32 << 20
	maxGeneratedImageDimension = 12_288
	maxGeneratedImagePixels    = 19_000_000
)

var imageProviderGateway *imagegen.Registry

type imageGenerationRequest = imagegen.Request

type resolvedImageRequest struct {
	request     imageGenerationRequest
	resolution  string
	aspectRatio string
	native      *imagegen.ResolvedRequest
}

type imageRequestError struct {
	message string
	param   string
}

func (e *imageRequestError) Error() string { return e.message }

func parseImageGenerationRequest(raw []byte) (*resolvedImageRequest, error) {
	resolved, err := imagegen.Parse(raw)
	if err != nil {
		var requestErr *imagegen.RequestError
		if errors.As(err, &requestErr) {
			return nil, &imageRequestError{message: requestErr.Message, param: requestErr.Param}
		}
		return nil, err
	}
	return &resolvedImageRequest{
		request: resolved.Request, resolution: resolved.Resolution,
		aspectRatio: resolved.AspectRatio, native: resolved,
	}, nil
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
	// DecodeConfig proves only that the image header is readable. A truncated
	// JPEG or PNG can still carry a valid header and the expected dimensions,
	// which would otherwise be settled and returned as a paid successful image.
	// Bound dimensions first, then decode the full payload so corrupt pixel data,
	// missing terminal markers, and checksum failures remain all-or-nothing
	// provider failures.
	if _, decodedFormat, decodeErr := image.Decode(bytes.NewReader(raw)); decodeErr != nil || decodedFormat != format {
		return nil, fmt.Errorf("provider returned invalid image bytes")
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
	return imagegen.GoogleNativeDimensions(resolution, aspectRatio)
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
	outputTokens := resolved.native.MaxOutputTokens()
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
	if resolved.native.Spec.Pricing == imagegen.PricingFixed &&
		(req.Provider == nil || !strings.EqualFold(req.Provider.Usage, "byok")) {
		req.AdditionalCostReservationMicrodollars = resolved.native.FixedCustomerCostMicrodollars()
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
	if resolved.native.Spec.Pricing != imagegen.PricingGeminiTokens {
		serveNativeImageAuthorized(
			ctx, conn, resolved, req, trGateway, authorization, invokeOptions[0],
			idempotencyKey, started,
		)
		return
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
		resolved.native.BilledGeminiOutputTokens(),
	)
	// The endpoint tariff is the published image-output rate. Gemini reports
	// thinking tokens in the same aggregate completion count even though those
	// tokens have a much lower provider price. Bill exactly the documented image
	// token tier; TrustedRouter absorbs any private reasoning overhead rather
	// than incorrectly charging it at the image rate. The public usage envelope
	// still reports the provider's complete output count.
	billedOutputTokens := resolved.native.BilledGeminiOutputTokens()
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

func serveNativeImageAuthorized(
	ctx context.Context,
	conn io.Writer,
	resolved *resolvedImageRequest,
	req *types.OpenAIChatRequest,
	trGateway *trustedrouter.Client,
	authorization *trustedrouter.Authorization,
	option llm.InvokeOptions,
	idempotencyKey string,
	started time.Time,
) {
	if imageProviderGateway == nil || option.Provider != resolved.native.Spec.Provider {
		refundImageGeneration(ctx, trGateway, authorization, 502, "image_provider_unavailable", started, req.Metadata)
		writeProviderError(conn, 502, "image provider unavailable")
		return
	}
	nativeRequest, routeErr := nativeImageRequestForRoute(resolved.native, option.UpstreamModel)
	if routeErr != nil {
		refundImageGeneration(ctx, trGateway, authorization, 502, "image_catalog_mismatch", started, req.Metadata)
		writeProviderError(conn, 502, "image provider catalog mismatch")
		return
	}
	generationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	clientClosed := cancelUserModelOnDisconnect(generationCtx, cancel, conn)
	result, err := imageProviderGateway.Generate(
		generationCtx, nativeRequest, option.ProviderAPIKey, idempotencyKey,
	)
	if err != nil {
		if clientClosed.Load() {
			refundImageGeneration(ctx, trGateway, authorization, 499, "client_closed", started, req.Metadata)
			return
		}
		status := 502
		providerStatus := 0
		var providerErr *imagegen.ProviderError
		if errors.As(err, &providerErr) {
			providerStatus = providerErr.StatusCode
			if providerErr.StatusCode >= 400 && providerErr.StatusCode < 500 {
				status = providerErr.StatusCode
			}
		}
		refundImageGeneration(ctx, trGateway, authorization, status, "image_provider_error", started, req.Metadata)
		fmt.Fprintf(
			os.Stderr,
			"enclave.images_native_failed model=%q provider=%q provider_status=%d error_class=%q\n",
			req.Model,
			option.Provider,
			providerStatus,
			fmt.Sprintf("%T", err),
		)
		writeProviderError(conn, status, "image generation failed")
		return
	}
	if clientClosed.Load() {
		refundImageGeneration(ctx, trGateway, authorization, 499, "client_closed", started, req.Metadata)
		return
	}
	if nativeRequest.Spec.Pricing == imagegen.PricingOpenAITokens &&
		(result.Usage.InputTokens <= 0 || result.Usage.OutputTokens <= 0) {
		refundImageGeneration(ctx, trGateway, authorization, 502, "missing_image_usage", started, req.Metadata)
		writeProviderError(conn, 502, "image generation failed")
		return
	}
	additionalCost := 0
	if nativeRequest.Spec.Pricing == imagegen.PricingFixed && strings.EqualFold(option.UsageType, "Credits") {
		additionalCost = nativeRequest.FixedCustomerCostMicrodollars()
	}
	usage := trustedrouter.Usage{
		RequestID: newRequestID(), InputTokens: result.Usage.InputTokens,
		OutputTokens: result.Usage.OutputTokens, AdditionalCostMicrodollars: additionalCost,
		ElapsedSeconds: maxDurationSeconds(time.Since(started), 0.001),
		FinishReason:   "stop", Streamed: nativeRequest.Request.Stream, RouteType: "images",
		SelectedModel: option.Model, SelectedEndpoint: option.EndpointID,
		User: req.User, SessionID: req.SessionID, Trace: req.Trace, Metadata: req.Metadata,
	}
	applyUsageAttribution(&usage, req)
	settlement, err := trGateway.Settle(ctx, authorization, usage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enclave.images_settle_failed model=%q err=%v\n", req.Model, err)
		writeSpentError(conn, 502, "settlement failed")
		return
	}
	data := make([]map[string]any, 0, len(result.Images))
	for _, image := range result.Images {
		data = append(data, map[string]any{"b64_json": image.B64, "media_type": image.MediaType})
	}
	responseUsage := map[string]any{
		"prompt_tokens":     result.Usage.InputTokens,
		"completion_tokens": result.Usage.OutputTokens,
		"total_tokens":      result.Usage.TotalTokens,
		"cost":              settlement.Cost,
	}
	if nativeRequest.Request.Stream {
		if err := writeResponseHead(conn, 200, "text/event-stream"); err != nil {
			return
		}
		chunked := newChunkedWriter(conn)
		for _, image := range result.Images {
			payload, _ := json.Marshal(map[string]any{
				"type": "image_generation.completed", "b64_json": image.B64,
				"media_type": image.MediaType, "created": result.Created, "usage": responseUsage,
			})
			_, _ = fmt.Fprintf(chunked, "data: %s\n\n", payload)
		}
		_, _ = io.WriteString(chunked, "data: [DONE]\n\n")
		_ = chunked.Close()
		return
	}
	payload, err := json.Marshal(map[string]any{
		"created": result.Created,
		"data":    data,
		"usage":   responseUsage,
	})
	if err != nil {
		writeSpentError(conn, 500, "image response encoding failed")
		return
	}
	writeJSONResponse(conn, 200, payload)
}

func nativeImageRequestForRoute(
	request *imagegen.ResolvedRequest,
	upstreamModel string,
) (*imagegen.ResolvedRequest, error) {
	if request == nil {
		return nil, fmt.Errorf("image request is unavailable")
	}
	clone := *request
	clone.Spec = request.Spec
	upstreamModel = strings.TrimSpace(upstreamModel)
	if upstreamModel == "" {
		return &clone, nil
	}
	if clone.Spec.Pricing == imagegen.PricingFixed && upstreamModel != clone.Spec.UpstreamID {
		return nil, fmt.Errorf("fixed-price image route does not match the catalog")
	}
	clone.Spec.UpstreamID = upstreamModel
	return &clone, nil
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
