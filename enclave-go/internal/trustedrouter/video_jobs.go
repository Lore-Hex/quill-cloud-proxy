package trustedrouter

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	qtypes "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

type VideoJob struct {
	ID                 string `json:"id"`
	WorkspaceID        string `json:"workspace_id"`
	KeyHash            string `json:"key_hash"`
	AuthorizationID    string `json:"authorization_id"`
	Model              string `json:"model"`
	Provider           string `json:"provider"`
	EndpointID         string `json:"endpoint_id"`
	ProviderModel      string `json:"provider_model"`
	QuotedMicrodollars int    `json:"quoted_microdollars"`
	InputMode          string `json:"input_mode"`
	DurationSeconds    int    `json:"duration_seconds"`
	Resolution         string `json:"resolution"`
	AspectRatio        string `json:"aspect_ratio"`
	GenerateAudio      bool   `json:"generate_audio"`
	Region             string `json:"region"`
	Status             string `json:"status"`
	ProviderJobID      string `json:"provider_job_id"`
	ProviderStatus     string `json:"provider_status"`
	GenerationID       string `json:"generation_id"`
	Attempts           int    `json:"attempts"`
	LeaseOwner         string `json:"lease_owner"`
	LastError          string `json:"last_error"`
	ContentExpiresAt   string `json:"content_expires_at"`
	CleanedAt          string `json:"cleaned_at"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
	Created            bool   `json:"created"`
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
	if job == nil {
		return nil, fmt.Errorf("trustedrouter: nil video job")
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
	if err := c.postJSONWithRetry(ctx, "/internal/gateway/video/jobs/prepare", body, &decoded, c.authorizeRetry); err != nil {
		return nil, err
	}
	return &decoded.Data, nil
}

func (c *Client) MarkVideoJobQueued(
	ctx context.Context,
	jobID, providerJobID, providerModel string,
	pollAfterSeconds int,
) (*VideoJob, error) {
	body := map[string]any{
		"provider_job_id":    providerJobID,
		"provider_model":     providerModel,
		"poll_after_seconds": pollAfterSeconds,
	}
	var decoded struct {
		Data VideoJob `json:"data"`
	}
	path := "/internal/gateway/video/jobs/" + strings.TrimSpace(jobID) + "/queued"
	if err := c.postJSONWithRetry(ctx, path, body, &decoded, c.authorizeRetry); err != nil {
		return nil, err
	}
	return &decoded.Data, nil
}

func (c *Client) LookupVideoJob(ctx context.Context, bearer, jobID string) (*VideoJob, error) {
	body := map[string]any{"api_key_lookup_hash": lookupHash(bearer)}
	var decoded struct {
		Data VideoJob `json:"data"`
	}
	path := "/internal/gateway/video/jobs/" + strings.TrimSpace(jobID) + "/lookup"
	if err := c.postJSON(ctx, path, body, &decoded); err != nil {
		return nil, err
	}
	return &decoded.Data, nil
}

func (c *Client) ClaimVideoJobs(
	ctx context.Context,
	leaseOwner string,
	limit, leaseSeconds int,
) ([]VideoJob, error) {
	body := map[string]any{
		"lease_owner": leaseOwner, "limit": limit, "lease_seconds": leaseSeconds,
	}
	var decoded struct {
		Data []VideoJob `json:"data"`
	}
	if err := c.postJSON(ctx, "/internal/gateway/video/jobs/claim", body, &decoded); err != nil {
		return nil, err
	}
	return decoded.Data, nil
}

func (c *Client) UpdateVideoJob(
	ctx context.Context,
	jobID, status, leaseOwner, providerStatus, generationID, errorCode string,
	pollAfterSeconds int,
) (*VideoJob, error) {
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
	path := "/internal/gateway/video/jobs/" + strings.TrimSpace(jobID) + "/update"
	if err := c.postJSON(ctx, path, body, &decoded); err != nil {
		return nil, err
	}
	return &decoded.Data, nil
}

func (c *Client) MarkVideoJobCleaned(ctx context.Context, jobID string) error {
	var decoded map[string]any
	path := "/internal/gateway/video/jobs/" + strings.TrimSpace(jobID) + "/cleaned"
	return c.postJSON(ctx, path, map[string]any{}, &decoded)
}
