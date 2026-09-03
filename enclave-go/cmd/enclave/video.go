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
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
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
		out, err := video.ModelsJSON()
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
	auth, err := s.control.AuthorizeVideo(
		ctx,
		bearer,
		resolved.Model.ID,
		idempotencyKey,
		videoRequestFingerprint(bearer, &req),
		req.Provider,
		reservationMicrodollars,
	)
	if err != nil {
		writeGatewayAuthorizationError(conn, err)
		return
	}
	routes := authorizedVideoRoutes(auth, quotes)
	if len(routes) == 0 {
		_ = s.control.Refund(ctx, auth, 503, "video_provider_unavailable", 0.001, nil)
		writeOpenAIError(conn, 503, "no authorized video provider supports this request", "server_error", "video_provider_unavailable", "")
		return
	}
	selected := routes[0]
	job := &trustedrouter.VideoJob{
		ID: videoJobID(auth.AuthorizationID), AuthorizationID: auth.AuthorizationID,
		WorkspaceID: auth.WorkspaceID, KeyHash: auth.APIKeyHash,
		Model: resolved.Model.ID, Provider: selected.Provider, EndpointID: selected.EndpointID,
		ProviderModel:      resolved.Model.ID,
		QuotedMicrodollars: selected.QuotedMicrodollars,
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

func quoteVideoProviders(
	ctx context.Context,
	providers []video.Provider,
	request *video.ResolvedRequest,
) (map[string]int, error) {
	quotes := make(map[string]int, len(providers))
	var lastErr error
	for _, provider := range providers {
		quoted, err := provider.QuoteResolved(ctx, request)
		if err != nil {
			lastErr = err
			continue
		}
		if quoted <= 0 {
			lastErr = fmt.Errorf("%s returned an invalid video quote", provider.ID())
			continue
		}
		quotes[provider.ID()] = quoted
	}
	return quotes, lastErr
}

func maximumVideoQuote(quotes map[string]int) int {
	maximum := 0
	for _, quote := range quotes {
		if quote > maximum {
			maximum = quote
		}
	}
	return maximum
}

func authorizedVideoRoutes(
	auth *trustedrouter.Authorization,
	quotes map[string]int,
) []authorizedVideoRoute {
	if auth == nil {
		return nil
	}
	routes := make([]authorizedVideoRoute, 0, len(auth.RouteCandidates)+1)
	seen := make(map[string]struct{}, len(auth.RouteCandidates)+1)
	appendRoute := func(provider, endpointID string) {
		quote, ok := quotes[provider]
		if !ok || endpointID == "" {
			return
		}
		if _, duplicate := seen[endpointID]; duplicate {
			return
		}
		seen[endpointID] = struct{}{}
		routes = append(routes, authorizedVideoRoute{
			Provider: provider, EndpointID: endpointID, QuotedMicrodollars: quote,
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
		settled, err := s.control.Settle(ctx, auth, trustedrouter.Usage{
			RequestID: "video-" + job.ID, InputTokens: 0, OutputTokens: 0,
			ElapsedSeconds: videoElapsed(job.CreatedAt), FinishReason: "completed",
			RouteType: "videos", SelectedModel: job.Model, SelectedEndpoint: job.EndpointID,
			AdditionalCostMicrodollars: job.QuotedMicrodollars,
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

func videoJobID(authorizationID string) string {
	digest := sha256.Sum256([]byte("trustedrouter-video:" + authorizationID))
	return "job-" + hex.EncodeToString(digest[:16])
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
		payload["usage"] = map[string]any{
			"cost":              microdollarsJSONNumber(job.QuotedMicrodollars),
			"cost_microdollars": job.QuotedMicrodollars,
			"is_byok":           false,
		}
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
