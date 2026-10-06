package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

var videoGateway *videoService

var videoLargeRequestSlots = make(chan struct{}, 2)

type videoService struct {
	providers *video.Registry
	control   *trustedrouter.Client
	workerID  string
}

const (
	videoPollActiveInterval = 5 * time.Second
	videoPollIdleMax        = 30 * time.Second
	videoPollErrorFloor     = 15 * time.Second
)

type videoPollState struct {
	consecutiveIdle int
}

func (p *videoPollState) nextDelay(workerID string, jobs int, pollErr error) time.Duration {
	base := videoPollActiveInterval
	if jobs > 0 {
		p.consecutiveIdle = 0
	} else {
		if p.consecutiveIdle < 8 {
			p.consecutiveIdle++
		}
		base <<= min(p.consecutiveIdle, 3)
		if base > videoPollIdleMax {
			base = videoPollIdleMax
		}
	}
	if pollErr != nil && base < videoPollErrorFloor {
		base = videoPollErrorFloor
	}
	return jitterVideoPoll(base, workerID, p.consecutiveIdle)
}

func jitterVideoPoll(base time.Duration, workerID string, generation int) time.Duration {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s#%d", workerID, generation)))
	// Stable per worker and backoff generation, in the range 85%..115%.
	percent := 85 + int(sum[0])%31
	return base * time.Duration(percent) / 100
}

func newVideoService(keys video.ProviderKeys, control *trustedrouter.Client) *videoService {
	return &videoService{
		providers: video.NewRegistry(keys, llm.NewProviderHTTPClient()),
		control:   control,
		workerID:  "video-" + randomHex(8),
	}
}

func (s *videoService) Enabled() bool {
	return s != nil && s.providers != nil && s.providers.Enabled() && s.control != nil && s.control.Enabled()
}

func (s *videoService) Start(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	go func() {
		state := videoPollState{}
		timer := time.NewTimer(jitterVideoPoll(2*time.Second, s.workerID, -1))
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				jobs, err := s.drain(ctx)
				timer.Reset(state.nextDelay(s.workerID, jobs, err))
			}
		}
	}()
}

func (s *videoService) drain(ctx context.Context) (int, error) {
	claimCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	jobs, err := s.control.ClaimVideoJobs(claimCtx, s.workerID, 8, 60)
	cancel()
	if err != nil {
		return 0, err
	}
	for i := range jobs {
		job := jobs[i]
		jobCtx, jobCancel := context.WithTimeout(ctx, 45*time.Second)
		_, _ = s.pollAndFinalize(jobCtx, &job, s.workerID)
		jobCancel()
	}
	return len(jobs), nil
}

func maybeServeVideoRoute(
	ctx context.Context,
	conn io.Writer,
	method, routePath string,
	body []byte,
	trGateway *trustedrouter.Client,
	bearer, idempotencyKey string,
) bool {
	if routePath != "/v1/videos" && routePath != "/v1/videos/models" && !strings.HasPrefix(routePath, "/v1/videos/") {
		return false
	}
	if videoGateway == nil || !videoGateway.Enabled() || trGateway == nil || !trGateway.Enabled() {
		writeOpenAIError(conn, 503, "video generation is temporarily unavailable", "server_error", "video_unavailable", "")
		return true
	}
	if routePath == "/v1/videos/models" {
		if method != http.MethodGet {
			writeOpenAIError(conn, 404, "route not found", "invalid_request_error", "not_found", "")
			return true
		}
		if err := trGateway.ValidateKey(ctx, bearer, "videos.models"); err != nil {
			writeErrorWithSourceHeaders(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "gateway authorization failed"), "router", retryHeadersFromControlPlaneError(err))
			return true
		}
		out, err := video.ModelsJSON(videoGateway.providers)
		if err != nil {
			writeOpenAIError(conn, 500, "could not serialize video models", "server_error", "internal_error", "")
			return true
		}
		writeJSONResponse(conn, 200, out)
		return true
	}
	if routePath == "/v1/videos" {
		if method != http.MethodPost {
			writeOpenAIError(conn, 404, "route not found", "invalid_request_error", "not_found", "")
			return true
		}
		videoGateway.serveCreate(ctx, conn, body, bearer, idempotencyKey)
		return true
	}
	jobID, content, ok := parseVideoJobPath(routePath)
	if !ok || method != http.MethodGet {
		writeOpenAIError(conn, 404, "route not found", "invalid_request_error", "not_found", "")
		return true
	}
	if content {
		videoGateway.serveContent(ctx, conn, bearer, jobID)
	} else {
		videoGateway.serveStatus(ctx, conn, bearer, jobID)
	}
	return true
}

func (s *videoService) serveCreate(ctx context.Context, conn io.Writer, body []byte, bearer, idempotencyKey string) {
	if len(body) > 1<<20 {
		select {
		case videoLargeRequestSlots <- struct{}{}:
			defer func() { <-videoLargeRequestSlots }()
		case <-ctx.Done():
			writeOpenAIError(conn, 499, "request canceled", "invalid_request_error", "client_closed", "")
			return
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var req video.CreateRequest
	if err := decoder.Decode(&req); err != nil {
		writeOpenAIError(conn, 400, "invalid video request", "invalid_request_error", "bad_request", "")
		return
	}
	resolved, err := video.ResolveRequest(&req)
	if err != nil {
		var unsupported *video.UnsupportedError
		if errors.As(err, &unsupported) {
			writeOpenAIError(conn, 501, unsupported.Error(), "not_supported_in_alpha", "not_supported_in_alpha", unsupported.Field)
			return
		}
		writeOpenAIError(conn, 400, err.Error(), "invalid_request_error", "bad_request", "")
		return
	}
	providers := s.providers.Supporting(resolved)
	authorizeCtx := ctx
	if req.Seed != nil {
		var preferences types.ProviderRouting
		policy, _ := json.Marshal(req.Provider)
		if err := json.Unmarshal(policy, &preferences); err != nil {
			writeOpenAIError(conn, 400, "invalid video provider preferences", "invalid_request_error", "bad_request", "provider")
			return
		}
		only := types.NormalizeProviderFilters(preferences.Only)
		ignore := types.NormalizeProviderFilters(preferences.Ignore)
		order := types.NormalizeProviderFilters(preferences.Order)
		allowed := func(id string) bool {
			return (len(only) == 0 || slices.Contains(only, id)) &&
				!slices.Contains(ignore, id) &&
				(preferences.AllowFallbacks == nil || *preferences.AllowFallbacks ||
					len(order) == 0 || slices.Contains(order, id))
		}
		eligible := make([]video.Provider, 0, len(providers))
		for _, provider := range providers {
			if allowed(provider.ID()) {
				eligible = append(eligible, provider)
			}
		}
		providers = eligible
		if len(providers) == 0 {
			// Before the policy filter, quoting could include BytePlus even when
			// the caller selected a fixed-price route. Its bound is computed
			// locally, independent of today's enabled credentials; no quote runs.
			historicalTokenLimit, _ := video.NewBytePlusClient("", nil).OutputTokenLimit(resolved)
			existing, err := s.control.LookupVideoReplay(ctx, bearer, resolved.Model.ID, idempotencyKey, videoRequestFingerprint(bearer, &req), req.Provider, historicalTokenLimit)
			if err != nil {
				writeGatewayAuthorizationError(conn, err)
				return
			}
			if existing != nil {
				writeVideoJobResponse(conn, http.StatusAccepted, existing)
				return
			}
			withoutSeed := *resolved
			withoutSeed.Seed = nil
			var routes []string
			for _, provider := range s.providers.Supporting(&withoutSeed) {
				if allowed(provider.ID()) {
					routes = append(routes, provider.ID())
				}
			}
			routeNames := strings.Join(routes, ", ")
			if routeNames == "" {
				routeNames = "none enabled"
			}
			message := fmt.Sprintf("seed is not supported for model %q on the allowed video routes (%s)", resolved.Model.ID, routeNames)
			writeOpenAIError(conn, 400, message, "invalid_request_error", "unsupported_parameter", "seed")
			return
		}
		// Derived constraints travel outside the fingerprinted authorization body.
		// Keep caller preferences intact so pre-rollout jobs remain replayable.
		capable := make([]string, 0, len(providers))
		for _, provider := range providers {
			capable = append(capable, provider.ID())
		}
		authorizeCtx = trustedrouter.WithVideoAllowedProviders(ctx, capable)
	}
	if len(providers) == 0 {
		writeOpenAIError(conn, 503, "no configured video provider supports this request", "server_error", "video_provider_unavailable", "")
		return
	}
	quoteCtx, cancelQuote := context.WithTimeout(ctx, 20*time.Second)
	quotes, quoteErr := quoteVideoProviders(quoteCtx, providers, resolved)
	cancelQuote()
	if len(quotes) == 0 {
		writeVideoProviderError(conn, quoteErr, "could not quote video generation")
		return
	}
	reservationMicrodollars := maximumVideoQuote(quotes)
	outputTokenLimit := maximumVideoTokenLimit(quotes)
	auth, existing, err := s.control.AuthorizeVideo(
		authorizeCtx,
		bearer,
		resolved.Model.ID,
		resolved.Resolution,
		idempotencyKey,
		videoRequestFingerprint(bearer, &req),
		req.Provider,
		reservationMicrodollars,
		outputTokenLimit,
	)
	if err != nil {
		writeGatewayAuthorizationError(conn, err)
		return
	}
	if existing != nil {
		writeVideoJobResponse(conn, http.StatusAccepted, existing)
		return
	}
	routes := authorizedVideoRoutes(auth, quotes, resolved.Resolution)
	if len(routes) == 0 && req.Seed == nil {
		if _, hasBytePlus := quotes["byteplus"]; hasBytePlus && resolved.Resolution == "1080p" && auth.VideoTariffResolution != "1080p" {
			_ = s.control.Refund(ctx, auth, 503, "video_tariff_unavailable", 0.001, nil)
			writeOpenAIError(conn, 503, "BytePlus 1080p billing requires a matching resolution tariff acknowledgment from the control plane", "server_error", "video_tariff_unavailable", "")
			return
		}
		_ = s.control.Refund(ctx, auth, 503, "video_provider_unavailable", 0.001, nil)
		writeOpenAIError(conn, 503, "no authorized video provider supports this request", "server_error", "video_provider_unavailable", "")
		return
	}
	// A rejected seeded authorization still needs a durable job at its billing
	// authority. Main's submitting-job recovery refunds it across restarts.
	routingUnavailable := len(routes) == 0
	selected := authorizedVideoRoute{
		Provider: auth.Provider, EndpointID: auth.EndpointID,
		QuotedMicrodollars: auth.AdditionalCostReservationMicrodollars,
	}
	if !routingUnavailable {
		selected = routes[0]
	}
	// Older control planes can authorize only fixed-price providers. Do not
	// send the new job field unless a token-billed route was actually admitted.
	outputTokenLimit = 0
	for _, route := range routes {
		outputTokenLimit = max(outputTokenLimit, quotes[route.Provider].OutputTokenLimit)
	}
	job := &trustedrouter.VideoJob{
		ID: trustedrouter.VideoJobID(auth.AuthorizationID), AuthorizationID: auth.AuthorizationID,
		WorkspaceID: auth.WorkspaceID, KeyHash: auth.APIKeyHash,
		Model: resolved.Model.ID, Provider: selected.Provider, EndpointID: selected.EndpointID,
		ProviderModel:      resolved.Model.ID,
		QuotedMicrodollars: selected.QuotedMicrodollars,
		OutputTokenLimit:   outputTokenLimit,
		InputMode:          resolved.InputMode, DurationSeconds: resolved.DurationSeconds,
		Resolution: resolved.Resolution, AspectRatio: resolved.AspectRatio,
		GenerateAudio: resolved.GenerateAudio, Region: auth.Region,
		Status:                  "submitting",
		ControlPlaneEndpoint:    auth.ControlPlaneEndpoint,
		ControlPlaneEndpointSet: auth.ControlPlaneEndpointSet,
	}
	stored, err := s.control.PrepareVideoJob(ctx, job)
	if err != nil {
		_ = s.control.Refund(ctx, auth, 503, "video_job_store_unavailable", 0.001, nil)
		writeOpenAIError(conn, 503, "video job storage is unavailable", "server_error", "video_job_store_unavailable", "")
		return
	}
	if !stored.Created {
		writeVideoJobResponse(conn, http.StatusAccepted, stored)
		return
	}
	if routingUnavailable {
		// Never make the row terminal before the hold is released. If either
		// call fails, the worker retries using the pinned submitting row.
		if err := s.control.Refund(ctx, auth, 503, "video_routing_unavailable", 0.001, nil); err == nil {
			_, _ = s.control.UpdateVideoJob(ctx, stored, "failed", "", "FAILED", "", "routing_unavailable", 5)
		}
		writeGatewayAuthorizationError(conn, trustedrouter.VideoRoutingUnavailable())
		return
	}
	selected, queued, err := s.queueVideoJob(ctx, resolved, routes)
	if err != nil {
		_ = s.control.Refund(ctx, auth, videoErrorStatus(err), "video_provider_error", 0.001, nil)
		_, _ = s.control.UpdateVideoJob(ctx, stored, "failed", "", "FAILED", "", "provider_error", 5)
		writeVideoProviderError(conn, err, "video provider rejected the job")
		return
	}
	stored, err = s.control.MarkVideoJobQueued(
		ctx, stored, queued.QueueID, selected.Provider, selected.EndpointID,
		queued.ProviderModel, selected.QuotedMicrodollars, 5,
	)
	if err != nil {
		// The provider may already be working. Do not submit a duplicate and do
		// not pretend the job failed; the deterministic idempotency record keeps
		// the hold bounded while operators repair this rare control-plane split.
		writeOpenAIError(conn, 503, "video job was queued but its status is temporarily unavailable", "server_error", "video_job_update_unavailable", "")
		return
	}
	writeVideoJobResponse(conn, http.StatusAccepted, stored)
}

type authorizedVideoRoute struct {
	Provider           string
	EndpointID         string
	QuotedMicrodollars int
}

type videoQuote struct {
	Microdollars     int
	OutputTokenLimit int
}

func quoteVideoProviders(
	ctx context.Context,
	providers []video.Provider,
	request *video.ResolvedRequest,
) (map[string]videoQuote, error) {
	quotes := make(map[string]videoQuote, len(providers))
	var lastErr error
	for _, provider := range providers {
		quoted, err := provider.QuoteResolved(ctx, request)
		if err != nil {
			lastErr = err
			continue
		}
		limit := 0
		if tokenProvider, ok := provider.(video.TokenBilledProvider); ok {
			limit, err = tokenProvider.OutputTokenLimit(request)
			if err != nil || limit <= 0 || limit > 2_000_000 || quoted != 0 {
				lastErr = fmt.Errorf("%s returned an invalid token reservation", provider.ID())
				continue
			}
		}
		if quoted < 0 || quoted == 0 && limit == 0 {
			lastErr = fmt.Errorf("%s returned an invalid video quote", provider.ID())
			continue
		}
		quotes[provider.ID()] = videoQuote{Microdollars: quoted, OutputTokenLimit: limit}
	}
	return quotes, lastErr
}

func maximumVideoQuote(quotes map[string]videoQuote) int {
	maximum := 0
	for _, quote := range quotes {
		if quote.Microdollars > maximum {
			maximum = quote.Microdollars
		}
	}
	return maximum
}

func maximumVideoTokenLimit(quotes map[string]videoQuote) int {
	maximum := 0
	for _, quote := range quotes {
		maximum = max(maximum, quote.OutputTokenLimit)
	}
	return maximum
}

func authorizedVideoRoutes(
	auth *trustedrouter.Authorization,
	quotes map[string]videoQuote,
	resolution string,
) []authorizedVideoRoute {
	if auth == nil {
		return nil
	}
	routes := make([]authorizedVideoRoute, 0, len(auth.RouteCandidates)+1)
	seen := make(map[string]struct{}, len(auth.RouteCandidates)+1)
	appendRoute := func(provider, endpointID string) {
		// Check after authorization (the echo is only known now), but before
		// preparing a job or paid queueing. Filter primary AND fallback routes.
		// Other authorized candidates can use the shared hold and settle their
		// own endpoint; if none remain, serveCreate refunds the entire hold.
		if provider == "byteplus" && resolution == "1080p" && auth.VideoTariffResolution != "1080p" {
			return
		}
		quote, ok := quotes[provider]
		if !ok || endpointID == "" {
			return
		}
		if _, duplicate := seen[endpointID]; duplicate {
			return
		}
		seen[endpointID] = struct{}{}
		routes = append(routes, authorizedVideoRoute{
			Provider: provider, EndpointID: endpointID, QuotedMicrodollars: quote.Microdollars,
		})
	}
	appendRoute(auth.Provider, auth.EndpointID)
	for _, candidate := range auth.RouteCandidates {
		appendRoute(candidate.Provider, candidate.EndpointID)
	}
	return routes
}

func (s *videoService) queueVideoJob(
	ctx context.Context,
	request *video.ResolvedRequest,
	routes []authorizedVideoRoute,
) (authorizedVideoRoute, *video.QueueResult, error) {
	var lastErr error
	for _, route := range routes {
		provider, ok := s.providers.Provider(route.Provider)
		if !ok || !provider.Supports(request) {
			continue
		}
		queueCtx, cancel := context.WithTimeout(ctx, video.QueueTimeout(provider))
		queued, err := provider.QueueResolved(queueCtx, request)
		cancel()
		if err == nil {
			return route, queued, nil
		}
		lastErr = err
		if !video.IsRetryableProviderError(err) {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no authorized video provider is configured")
	}
	return authorizedVideoRoute{}, nil, lastErr
}

func (s *videoService) serveStatus(ctx context.Context, conn io.Writer, bearer, jobID string) {
	job, err := s.control.LookupVideoJob(ctx, bearer, jobID)
	if err != nil {
		writeErrorWithSourceHeaders(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "video job lookup failed"), "router", retryHeadersFromControlPlaneError(err))
		return
	}
	if job.Status == "pending" || job.Status == "in_progress" {
		job, err = s.pollAndFinalize(ctx, job, "")
		if err != nil {
			writeVideoProviderError(conn, err, "could not poll video job")
			return
		}
	}
	writeVideoJobResponse(conn, 200, job)
}

func (s *videoService) serveContent(ctx context.Context, conn io.Writer, bearer, jobID string) {
	job, err := s.control.LookupVideoJob(ctx, bearer, jobID)
	if err != nil {
		writeErrorWithSourceHeaders(conn, statusFromControlPlaneError(err), messageFromControlPlaneError(err, "video job lookup failed"), "router", retryHeadersFromControlPlaneError(err))
		return
	}
	if job.CleanedAt != "" {
		writeOpenAIError(conn, 410, "video content has already been retrieved", "invalid_request_error", "content_expired", "")
		return
	}
	if job.Status == "failed" {
		writeOpenAIError(conn, 502, "video generation failed", "provider_error", "video_generation_failed", "")
		return
	}
	if job.Status == "submitting" {
		writeOpenAIError(conn, 409, "video is not ready", "invalid_request_error", "video_not_ready", "")
		return
	}
	if job.Status != "completed" {
		job, err = s.pollAndFinalize(ctx, job, "")
		if err != nil {
			writeVideoProviderError(conn, err, "could not poll video job")
			return
		}
		if job.Status != "completed" {
			if job.Status == "failed" {
				writeOpenAIError(conn, 502, "video generation failed", "provider_error", "video_generation_failed", "")
				return
			}
			writeOpenAIError(conn, 409, "video is not ready", "invalid_request_error", "video_not_ready", "")
			return
		}
	}
	provider, ok := s.providers.Provider(job.Provider)
	if !ok {
		writeOpenAIError(conn, 503, "video provider is temporarily unavailable", "server_error", "video_provider_unavailable", "")
		return
	}
	result, err := provider.Retrieve(ctx, job.ProviderModel, job.ProviderJobID)
	if err != nil {
		writeVideoProviderError(conn, err, "could not retrieve video content")
		return
	}
	if result.Body == nil {
		if result.DownloadURL == "" {
			writeOpenAIError(conn, 502, "provider did not return streamable video content", "server_error", "video_content_unavailable", "")
			return
		}
		result, err = provider.Download(ctx, result.DownloadURL)
		if err != nil {
			writeVideoProviderError(conn, err, "could not download video content")
			return
		}
	}
	defer result.Body.Close()
	contentType := result.ContentType
	if contentType == "" {
		contentType = "video/mp4"
	}
	if err := writeVideoResponseHead(conn, contentType, job.ID); err != nil {
		return
	}
	chunked := newChunkedWriter(conn)
	_, copyErr := io.Copy(chunked, result.Body)
	if copyErr != nil {
		_ = chunked.Close()
		return
	}
	if closeErr := chunked.Complete(); closeErr != nil {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	if err := provider.Complete(cleanupCtx, job.ProviderModel, job.ProviderJobID); err == nil {
		_ = s.control.MarkVideoJobCleaned(cleanupCtx, job)
	}
	cancel()
}

func (s *videoService) pollAndFinalize(ctx context.Context, job *trustedrouter.VideoJob, leaseOwner string) (*trustedrouter.VideoJob, error) {
	if job == nil {
		return job, nil
	}
	if job.Status == "submitting" && job.ProviderJobID == "" {
		auth := authorizationForVideoJob(job)
		if err := s.control.Refund(ctx, auth, 503, "video_submission_interrupted", 0.001, nil); err != nil {
			return job, err
		}
		updated, err := s.control.UpdateVideoJob(ctx, job, "failed", leaseOwner, "SUBMISSION_INTERRUPTED", "", "submission_interrupted", 5)
		if err != nil {
			return job, err
		}
		return updated, nil
	}
	if job.ProviderJobID == "" {
		return job, nil
	}
	provider, ok := s.providers.Provider(job.Provider)
	if !ok {
		return job, fmt.Errorf("video provider %s is not configured", job.Provider)
	}
	if job.Status == "failed" {
		return job, nil
	}
	if job.Status == "completed" {
		if job.CleanedAt != "" {
			return job, nil
		}
		if err := provider.Complete(ctx, job.ProviderModel, job.ProviderJobID); err != nil {
			return job, err
		}
		if err := s.control.MarkVideoJobCleaned(ctx, job); err != nil {
			return job, err
		}
		job.CleanedAt = time.Now().UTC().Format(time.RFC3339)
		return job, nil
	}
	result, err := provider.Retrieve(ctx, job.ProviderModel, job.ProviderJobID)
	if err != nil {
		var httpErr *video.HTTPError
		if errors.As(err, &httpErr) && !httpErr.Retryable {
			auth := authorizationForVideoJob(job)
			_ = s.control.Refund(ctx, auth, httpErr.Status, "video_provider_error", 0.001, nil)
			updated, updateErr := s.control.UpdateVideoJob(ctx, job, "failed", leaseOwner, "FAILED", "", "provider_error", 5)
			if updateErr == nil {
				return updated, nil
			}
		}
		if leaseOwner != "" {
			_, _ = s.control.UpdateVideoJob(ctx, job, "in_progress", leaseOwner, "RETRY", "", "", 10)
		}
		return job, err
	}
	if result.Body != nil {
		result.Body.Close()
	}
	switch result.State {
	case video.PollProcessing:
		updated, err := s.control.UpdateVideoJob(ctx, job, "in_progress", leaseOwner, result.ProviderStatus, "", "", 5)
		if err != nil {
			return job, err
		}
		return updated, nil
	case video.PollFailed:
		auth := authorizationForVideoJob(job)
		if err := s.control.Refund(ctx, auth, 502, "video_provider_failed", 0.001, nil); err != nil {
			return job, err
		}
		updated, err := s.control.UpdateVideoJob(ctx, job, "failed", leaseOwner, result.ProviderStatus, "", "provider_failed", 5)
		if err != nil {
			return job, err
		}
		return updated, nil
	case video.PollCompleted:
		auth := authorizationForVideoJob(job)
		outputTokens, fixedCost := 0, job.QuotedMicrodollars
		if _, tokenBilled := provider.(video.TokenBilledProvider); tokenBilled {
			if fixedCost != 0 || job.OutputTokenLimit <= 0 || result.OutputTokens <= 0 || result.OutputTokens > job.OutputTokenLimit {
				return job, fmt.Errorf("video provider returned usage outside the authorized token bound")
			}
			outputTokens = result.OutputTokens
		} else if fixedCost <= 0 {
			return job, fmt.Errorf("fixed-price video job has no authorized quote")
		}
		settled, err := s.control.Settle(ctx, auth, trustedrouter.Usage{
			RequestID: "video-" + job.ID, InputTokens: 0, OutputTokens: outputTokens,
			ElapsedSeconds: videoElapsed(job.CreatedAt), FinishReason: "completed",
			RouteType: "videos", SelectedModel: job.Model, SelectedEndpoint: job.EndpointID,
			AdditionalCostMicrodollars: fixedCost,
			VideoInputMode:             job.InputMode, VideoDurationSeconds: job.DurationSeconds,
			VideoResolution: job.Resolution, VideoAspectRatio: job.AspectRatio,
			VideoGenerateAudio: job.GenerateAudio,
		})
		if err != nil {
			return job, err
		}
		updated, err := s.control.UpdateVideoJob(ctx, job, "completed", leaseOwner, result.ProviderStatus, settled.GenerationID, "", 5)
		if err != nil {
			return job, err
		}
		return updated, nil
	default:
		return job, fmt.Errorf("unknown video provider status")
	}
}

func authorizationForVideoJob(job *trustedrouter.VideoJob) *trustedrouter.Authorization {
	return &trustedrouter.Authorization{
		AuthorizationID: job.AuthorizationID, WorkspaceID: job.WorkspaceID,
		APIKeyHash: job.KeyHash, Model: job.Model, RequestedModel: job.Model,
		EndpointID: job.EndpointID, Provider: job.Provider,
		AdditionalCostReservationMicrodollars: job.QuotedMicrodollars,
		RouteType:                             "videos",
		ControlPlaneEndpoint:                  job.ControlPlaneEndpoint,
		ControlPlaneEndpointSet:               job.ControlPlaneEndpointSet,
	}
}

func parseVideoJobPath(path string) (string, bool, bool) {
	rest := strings.TrimPrefix(path, "/v1/videos/")
	if rest == path || rest == "" {
		return "", false, false
	}
	content := strings.HasSuffix(rest, "/content")
	if content {
		rest = strings.TrimSuffix(rest, "/content")
	}
	if rest == "" || strings.Contains(rest, "/") || !strings.HasPrefix(rest, "job-") {
		return "", false, false
	}
	return rest, content, true
}

func videoRequestFingerprint(bearer string, req *video.CreateRequest) string {
	canonical, err := json.Marshal(req)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(bearer))
	_, _ = mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

func writeVideoJobResponse(conn io.Writer, status int, job *trustedrouter.VideoJob) {
	if job == nil {
		writeOpenAIError(conn, 500, "video job unavailable", "server_error", "internal_error", "")
		return
	}
	publicStatus := job.Status
	if publicStatus == "submitting" {
		publicStatus = "pending"
	}
	payload := map[string]any{
		"id":          job.ID,
		"polling_url": "/v1/videos/" + job.ID,
		"status":      publicStatus,
	}
	if job.GenerationID != "" {
		payload["generation_id"] = job.GenerationID
	}
	if publicStatus == "completed" && job.CleanedAt == "" {
		payload["unsigned_urls"] = []string{"/v1/videos/" + job.ID + "/content"}
		if job.ContentExpiresAt != "" {
			payload["expires_at"] = job.ContentExpiresAt
		}
	}
	if publicStatus == "completed" {
		usage := map[string]any{"is_byok": false}
		cost := job.SettledMicrodollars
		if cost == nil && job.QuotedMicrodollars > 0 {
			cost = &job.QuotedMicrodollars
		}
		if cost != nil {
			usage["cost"], usage["cost_microdollars"] = microdollarsJSONNumber(*cost), *cost
		}
		if job.OutputTokens != nil {
			usage["completion_tokens"], usage["total_tokens"] = *job.OutputTokens, *job.OutputTokens
		}
		payload["usage"] = usage
	}
	if publicStatus == "failed" {
		payload["error"] = "video generation failed"
	}
	body, _ := json.Marshal(payload)
	writeJSONResponse(conn, status, body)
}

func writeVideoResponseHead(conn io.Writer, contentType, jobID string) error {
	_, err := fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: %s\r\nContent-Disposition: attachment; filename=%q\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: %s\r\n\r\n",
		contentType,
		jobID+".mp4",
		responseConnection(conn),
	)
	return err
}

func microdollarsJSONNumber(value int) json.Number {
	whole := value / 1_000_000
	fraction := value % 1_000_000
	if fraction == 0 {
		return json.Number(fmt.Sprintf("%d", whole))
	}
	return json.Number(strings.TrimRight(fmt.Sprintf("%d.%06d", whole, fraction), "0"))
}

func writeVideoProviderError(conn io.Writer, err error, fallback string) {
	var inputErr *video.InputError
	if errors.As(err, &inputErr) {
		writeOpenAIError(conn, http.StatusBadRequest, inputErr.Error(), "invalid_request_error", "invalid_video_input", "input_references")
		return
	}
	status := videoErrorStatus(err)
	code := "video_provider_error"
	if status == 429 {
		code = "rate_limit_exceeded"
	}
	writeOpenAIError(conn, status, fallback, "provider_error", code, "")
}

func videoErrorStatus(err error) int {
	var inputErr *video.InputError
	if errors.As(err, &inputErr) {
		return http.StatusBadRequest
	}
	var httpErr *video.HTTPError
	if errors.As(err, &httpErr) {
		if httpErr.Status >= 400 && httpErr.Status <= 599 {
			return httpErr.Status
		}
	}
	return 502
}

func videoElapsed(createdAt string) float64 {
	created, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return 0.001
	}
	elapsed := time.Since(created).Seconds()
	if elapsed < 0.001 {
		return 0.001
	}
	return elapsed
}

func randomHex(bytesCount int) string {
	buf := make([]byte, bytesCount)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
