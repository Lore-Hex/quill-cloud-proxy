package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
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

func (c *Client) AuthorizeVideo(
	ctx context.Context,
	bearer, model, idempotencyKey, requestFingerprint string,
	provider map[string]any,
	quotedMicrodollars int,
) (*Authorization, error) {
	if quotedMicrodollars <= 0 {
		return nil, fmt.Errorf("trustedrouter: video quote must be positive")
	}
	one := 1
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
	req := &qtypes.OpenAIChatRequest{
		Model:                                 model,
		MaxTokens:                             &one,
		IdempotencyKey:                        idempotencyKey,
		RequestFingerprint:                    requestFingerprint,
		Provider:                              routing,
		AdditionalCostReservationMicrodollars: quotedMicrodollars,
	}
	return c.AuthorizeWithRoute(ctx, bearer, req, "videos")
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
	body := map[string]any{"api_key_lookup_hash": requestLookupHash(ctx, bearer)}
	path := "/internal/gateway/video/jobs/" + strings.TrimSpace(jobID) + "/lookup"
	var lastErr error
	for endpoint := range c.baseURLs {
		var decoded struct {
			Data VideoJob `json:"data"`
		}
		_, err := c.postJSONAtEndpoint(ctx, path, body, &decoded, endpoint)
		if err == nil {
			decoded.Data.pinControlPlaneEndpoint(endpoint)
			return &decoded.Data, nil
		}
		lastErr = err
		var controlErr *ControlPlaneError
		if errors.As(err, &controlErr) && controlErr.StatusCode == http.StatusNotFound {
			continue
		}
		if isDialFailure(err) {
			continue
		}
		return nil, err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("trustedrouter: no control-plane endpoint configured")
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
