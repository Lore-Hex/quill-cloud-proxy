package trustedrouter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type VideoJob struct {
	ID                      string `json:"id"`
	WorkspaceID             string `json:"workspace_id"`
	KeyHash                 string `json:"key_hash"`
	AuthorizationID         string `json:"authorization_id"`
	Model                   string `json:"model"`
	Provider                string `json:"provider"`
	EndpointID              string `json:"endpoint_id"`
	ProviderModel           string `json:"provider_model"`
	QuotedMicrodollars      int    `json:"quoted_microdollars"`
	OutputTokenLimit        int    `json:"output_token_limit,omitempty"`
	SettledMicrodollars     *int   `json:"settled_microdollars,omitempty"`
	OutputTokens            *int   `json:"output_tokens,omitempty"`
	InputMode               string `json:"input_mode"`
	DurationSeconds         int    `json:"duration_seconds"`
	Resolution              string `json:"resolution"`
	AspectRatio             string `json:"aspect_ratio"`
	GenerateAudio           bool   `json:"generate_audio"`
	Region                  string `json:"region"`
	Status                  string `json:"status"`
	ProviderJobID           string `json:"provider_job_id"`
	ProviderStatus          string `json:"provider_status"`
	GenerationID            string `json:"generation_id"`
	Attempts                int    `json:"attempts"`
	LeaseOwner              string `json:"lease_owner"`
	LastError               string `json:"last_error"`
	ContentExpiresAt        string `json:"content_expires_at"`
	CleanedAt               string `json:"cleaned_at"`
	CreatedAt               string `json:"created_at"`
	UpdatedAt               string `json:"updated_at"`
	Created                 bool   `json:"created"`
	ControlPlaneEndpoint    int    `json:"-"`
	ControlPlaneEndpointSet bool   `json:"-"`
}

func (job *VideoJob) pinControlPlaneEndpoint(endpoint int) {
	if job == nil || endpoint < 0 {
		return
	}
	job.ControlPlaneEndpoint = endpoint
	job.ControlPlaneEndpointSet = true
}

func (job *VideoJob) pinnedControlPlaneEndpoint() int {
	if job == nil || !job.ControlPlaneEndpointSet {
		return -1
	}
	return job.ControlPlaneEndpoint
}

func (c *Client) videoJobControlPlaneEndpoint(job *VideoJob) (int, error) {
	if job == nil {
		return -1, fmt.Errorf("trustedrouter: nil video job")
	}
	if endpoint := job.pinnedControlPlaneEndpoint(); endpoint >= 0 {
		if endpoint >= len(c.baseURLs) {
			return -1, fmt.Errorf("trustedrouter: invalid video job control-plane endpoint index %d", endpoint)
		}
		return endpoint, nil
	}
	if len(c.baseURLs) == 1 {
		return 0, nil
	}
	return -1, fmt.Errorf("trustedrouter: video job has no pinned control-plane authority")
}

// videoReplayLookup carries identity only, never an authorization to dispatch.
// All callers except AuthorizeVideo still see the ordinary replay conflict.
type videoReplayLookup struct {
	conflict error
	job      VideoJob
}

func (e *videoReplayLookup) Error() string { return e.conflict.Error() }
func (e *videoReplayLookup) Unwrap() error { return e.conflict }

func videoReplayConflict(body map[string]any, auth *Authorization, endpoint int) error {
	conflict := idempotencyReplayConflict()
	key, _ := body["idempotency_key"].(string)
	fingerprint, _ := body["request_fingerprint"].(string)
	if body["route_type"] != "videos" || key == "" || len(fingerprint) != 64 || endpoint < 0 ||
		auth.AuthorizationID == "" || auth.APIKeyHash == "" || auth.WorkspaceID == "" || auth.Model == "" {
		return conflict
	}
	return &videoReplayLookup{conflict: conflict, job: VideoJob{
		ID: VideoJobID(auth.AuthorizationID), AuthorizationID: auth.AuthorizationID,
		WorkspaceID: auth.WorkspaceID, KeyHash: auth.APIKeyHash, Model: auth.Model,
		ControlPlaneEndpoint: endpoint, ControlPlaneEndpointSet: true,
	}}
}

// VideoJobID is stable across regions and retries of the same authorization.
func VideoJobID(authorizationID string) string {
	digest := sha256.Sum256([]byte("trustedrouter-video:" + authorizationID))
	return "job-" + hex.EncodeToString(digest[:16])
}

// videoAllowedProvidersKey carries enclave-derived routing constraints outside
// the logical request body, which older routers include in their fingerprint.
type videoAllowedProvidersKey struct{}

// WithVideoAllowedProviders restricts fresh video authorization to these provider
// IDs. The router must enforce the internal header before selecting new routes;
// callers must filter returned routes against their eligible quotes before
// dispatch. Replays retain the original job and never dispatch.
func WithVideoAllowedProviders(ctx context.Context, providers []string) context.Context {
	return context.WithValue(ctx, videoAllowedProvidersKey{}, slices.Clone(providers))
}

func videoAllowedProviders(ctx context.Context) []string {
	providers, _ := ctx.Value(videoAllowedProvidersKey{}).([]string)
	return providers
}

// AuthorizeVideo returns either fresh dispatch authority or an existing job.
// A cross-invocation replay can only read; it cannot recreate a missing job.
func (c *Client) AuthorizeVideo(
	ctx context.Context,
	bearer, model, resolution, idempotencyKey, requestFingerprint string,
	provider map[string]any,
	quotedMicrodollars int,
	tokenLimits ...int,
) (*Authorization, *VideoJob, error) {
	limit := 0
	if len(tokenLimits) > 1 {
		return nil, nil, fmt.Errorf("trustedrouter: invalid video token limit")
	}
	if len(tokenLimits) == 1 {
		limit = tokenLimits[0]
	}
	if quotedMicrodollars < 0 || limit < 0 || limit > 2_000_000 || quotedMicrodollars == 0 && limit == 0 {
		return nil, nil, fmt.Errorf("trustedrouter: video requires a positive quote or token limit")
	}
	maxTokens := max(1, limit)
	req, err := videoAuthorizationRequest(model, idempotencyKey, requestFingerprint, provider, maxTokens, quotedMicrodollars)
	if err != nil {
		return nil, nil, err
	}
	// The resolution tariff contract covers these three values only. Other
	// existing fixed-quote video resolutions (e.g. 2K/4K) keep legacy behavior.
	switch resolution {
	case "480p", "720p", "1080p":
		req.VideoResolution = resolution
	}
	auth, err := c.AuthorizeWithRoute(ctx, bearer, req, "videos")
	var replay *videoReplayLookup
	if !errors.As(err, &replay) {
		return auth, nil, err
	}
	job, err := c.recoverVideoReplay(ctx, bearer, model, replay)
	return nil, job, err
}

func (c *Client) recoverVideoReplay(ctx context.Context, bearer, model string, replay *videoReplayLookup) (*VideoJob, error) {
	if replay.job.Model != model {
		return nil, replay.conflict
	}
	lookupHash, err := c.beforeCredentialCheck(ctx, bearer)
	if err != nil {
		return nil, err
	}
	job, err := c.lookupVideoJobAtEndpoint(ctx, lookupHash, replay.job.ID, replay.job.ControlPlaneEndpoint)
	c.afterCredentialCheck(ctx, lookupHash, err)
	var controlErr *ControlPlaneError
	if errors.As(err, &controlErr) && controlErr.StatusCode == http.StatusNotFound {
		// The original invocation may still be preparing its job. Never take over.
		return nil, replay.conflict
	}
	if err != nil {
		return nil, err
	}
	if job.ID != replay.job.ID || job.AuthorizationID != replay.job.AuthorizationID ||
		job.KeyHash != replay.job.KeyHash || job.WorkspaceID != replay.job.WorkspaceID || job.Model != model {
		return nil, replay.conflict
	}
	job.Created = false
	return job, nil
}

func (c *Client) PrepareVideoJob(ctx context.Context, job *VideoJob) (*VideoJob, error) {
	endpoint, err := c.videoJobControlPlaneEndpoint(job)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"job_id": job.ID, "authorization_id": job.AuthorizationID,
		"model": job.Model, "provider": job.Provider,
		"endpoint_id": job.EndpointID, "provider_model": job.ProviderModel,
		"quoted_microdollars": job.QuotedMicrodollars,
		"input_mode":          job.InputMode, "duration_seconds": job.DurationSeconds,
		"resolution": job.Resolution, "aspect_ratio": job.AspectRatio,
		"generate_audio": job.GenerateAudio, "region": job.Region,
	}
	if job.OutputTokenLimit > 0 {
		body["output_token_limit"] = job.OutputTokenLimit
	}
	var decoded struct {
		Data VideoJob `json:"data"`
	}
	selectedEndpoint, err := c.postJSONWithRetryFromEndpoint(
		ctx,
		"/internal/gateway/video/jobs/prepare",
		body,
		&decoded,
		c.authorizeRetry,
		endpoint,
	)
	if err != nil {
		return nil, err
	}
	decoded.Data.pinControlPlaneEndpoint(selectedEndpoint)
	return &decoded.Data, nil
}

func (c *Client) MarkVideoJobQueued(
	ctx context.Context,
	job *VideoJob,
	providerJobID, provider, endpointID, providerModel string,
	quotedMicrodollars int,
	pollAfterSeconds int,
) (*VideoJob, error) {
	pinnedEndpoint, err := c.videoJobControlPlaneEndpoint(job)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"provider_job_id":     providerJobID,
		"provider":            provider,
		"endpoint_id":         endpointID,
		"provider_model":      providerModel,
		"quoted_microdollars": quotedMicrodollars,
		"poll_after_seconds":  pollAfterSeconds,
	}
	var decoded struct {
		Data VideoJob `json:"data"`
	}
	path := "/internal/gateway/video/jobs/" + strings.TrimSpace(job.ID) + "/queued"
	selectedEndpoint, err := c.postJSONWithRetryFromEndpoint(
		ctx, path, body, &decoded, c.authorizeRetry, pinnedEndpoint,
	)
	if err != nil {
		return nil, err
	}
	decoded.Data.pinControlPlaneEndpoint(selectedEndpoint)
	return &decoded.Data, nil
}

func (c *Client) LookupVideoJob(ctx context.Context, bearer, jobID string) (*VideoJob, error) {
	lookupHash, err := c.beforeCredentialCheck(ctx, bearer)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for endpoint := range c.baseURLs {
		job, err := c.lookupVideoJobAtEndpoint(ctx, lookupHash, jobID, endpoint)
		if err == nil {
			c.afterCredentialCheck(ctx, lookupHash, nil)
			return job, nil
		}
		lastErr = err
		var controlErr *ControlPlaneError
		if errors.As(err, &controlErr) && controlErr.StatusCode == http.StatusNotFound {
			continue
		}
		if isDialFailure(err) {
			continue
		}
		c.afterCredentialCheck(ctx, lookupHash, err)
		return nil, err
	}
	if lastErr != nil {
		c.afterCredentialCheck(ctx, lookupHash, lastErr)
		return nil, lastErr
	}
	return nil, fmt.Errorf("trustedrouter: no control-plane endpoint configured")
}

func (c *Client) lookupVideoJobAtEndpoint(ctx context.Context, lookupHash, jobID string, endpoint int) (*VideoJob, error) {
	body := map[string]any{"api_key_lookup_hash": lookupHash}
	path := "/internal/gateway/video/jobs/" + strings.TrimSpace(jobID) + "/lookup"
	var decoded struct {
		Data VideoJob `json:"data"`
	}
	if _, err := c.postJSONAtEndpoint(ctx, path, body, &decoded, endpoint); err != nil {
		return nil, err
	}
	decoded.Data.pinControlPlaneEndpoint(endpoint)
	return &decoded.Data, nil
}

func (c *Client) ClaimVideoJobs(
	ctx context.Context,
	leaseOwner string,
	limit, leaseSeconds int,
) ([]VideoJob, error) {
	if len(c.baseURLs) == 0 {
		return nil, fmt.Errorf("trustedrouter: no control-plane endpoint configured")
	}
	jobs := make([]VideoJob, 0, limit)
	var firstErr error
	succeeded := 0
	for endpoint := range c.baseURLs {
		remaining := limit - len(jobs)
		if remaining <= 0 {
			break
		}
		body := map[string]any{
			"lease_owner": leaseOwner, "limit": remaining, "lease_seconds": leaseSeconds,
		}
		var decoded struct {
			Data []VideoJob `json:"data"`
		}
		if _, err := c.postJSONAtEndpoint(
			ctx, "/internal/gateway/video/jobs/claim", body, &decoded, endpoint,
		); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		succeeded++
		for i := range decoded.Data {
			decoded.Data[i].pinControlPlaneEndpoint(endpoint)
		}
		jobs = append(jobs, decoded.Data...)
	}
	if succeeded == 0 && firstErr != nil {
		return nil, firstErr
	}
	if firstErr != nil {
		fmt.Fprintf(os.Stderr, "enclave.video_claim_partial_failure err=%q\n", firstErr.Error())
	}
	return jobs, nil
}

func (c *Client) UpdateVideoJob(
	ctx context.Context,
	job *VideoJob,
	status, leaseOwner, providerStatus, generationID, errorCode string,
	pollAfterSeconds int,
) (*VideoJob, error) {
	pinnedEndpoint, err := c.videoJobControlPlaneEndpoint(job)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"status":             status,
		"poll_after_seconds": pollAfterSeconds,
	}
	if leaseOwner != "" {
		body["lease_owner"] = leaseOwner
	}
	if providerStatus != "" {
		body["provider_status"] = providerStatus
	}
	if generationID != "" {
		body["generation_id"] = generationID
	}
	if errorCode != "" {
		body["error"] = errorCode
	}
	var decoded struct {
		Data VideoJob `json:"data"`
	}
	path := "/internal/gateway/video/jobs/" + strings.TrimSpace(job.ID) + "/update"
	selectedEndpoint, err := c.postJSONAtEndpoint(
		ctx, path, body, &decoded, pinnedEndpoint,
	)
	if err != nil {
		return nil, err
	}
	decoded.Data.pinControlPlaneEndpoint(selectedEndpoint)
	return &decoded.Data, nil
}

func (c *Client) MarkVideoJobCleaned(ctx context.Context, job *VideoJob) error {
	pinnedEndpoint, err := c.videoJobControlPlaneEndpoint(job)
	if err != nil {
		return err
	}
	var decoded map[string]any
	path := "/internal/gateway/video/jobs/" + strings.TrimSpace(job.ID) + "/cleaned"
	_, err = c.postJSONAtEndpoint(
		ctx, path, map[string]any{}, &decoded, pinnedEndpoint,
	)
	return err
}

func videoAuthorizationRequest(model, idempotencyKey, requestFingerprint string, provider map[string]any, maxTokens, quotedMicrodollars int) (*qtypes.OpenAIChatRequest, error) {
	var routing *qtypes.ProviderRouting
	if len(provider) > 0 {
		raw, err := json.Marshal(provider)
		if err != nil {
			return nil, fmt.Errorf("trustedrouter: invalid video provider routing")
		}
		var parsed qtypes.ProviderRouting
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("trustedrouter: invalid video provider routing")
		}
		routing = &parsed
	}
	return &qtypes.OpenAIChatRequest{
		Model:                                 model,
		MaxTokens:                             &maxTokens,
		IdempotencyKey:                        idempotencyKey,
		RequestFingerprint:                    requestFingerprint,
		Provider:                              routing,
		AdditionalCostReservationMicrodollars: quotedMicrodollars,
	}, nil
}
