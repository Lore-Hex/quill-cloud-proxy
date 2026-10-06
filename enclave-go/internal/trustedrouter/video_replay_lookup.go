package trustedrouter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// LookupVideoReplay is read-only, including on a miss. Never emulate it using
// /authorize or a header that old routers might ignore: either can open a hold.
// A nil job is definitive only after every configured authority reports a miss.
func (c *Client) LookupVideoReplay(ctx context.Context, bearer, model, idempotencyKey, fingerprint string, provider map[string]any, historicalTokenLimits ...int) (*VideoJob, error) {
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		return nil, nil
	}
	if len(fingerprint) != 64 {
		return nil, idempotencyReplayConflict()
	}
	limits := []int{1}
	for _, limit := range historicalTokenLimits {
		if limit < 0 || limit > 2_000_000 {
			return nil, fmt.Errorf("trustedrouter: invalid video token limit")
		}
		if limit > 1 {
			limits = append(limits, limit)
		}
	}
	req, err := videoAuthorizationRequest(model, idempotencyKey, fingerprint, provider, 1, 0)
	if err != nil {
		return nil, err
	}
	lookupHash, err := c.beforeCredentialCheck(ctx, bearer)
	if err != nil {
		return nil, err
	}
	body := chatAuthorizeBody(c, lookupHash, idempotencyKey, req, "videos")
	const path = "/internal/gateway/video/replay-lookup"
	var unavailable error
	for endpoint := range c.baseURLs {
		var decoded struct {
			Data struct {
				Found         *bool          `json:"found"`
				Authorization *Authorization `json:"authorization"`
			} `json:"data"`
		}
		// Older enclaves quoted every available provider before routing policy
		// filtering. Try only historical reservation shapes of this SAME keyed
		// content fingerprint. These reads cannot reserve or dispatch on a miss.
		var err error
		for i, limit := range limits {
			body["max_tokens"], body["max_output_tokens"] = limit, limit
			_, err = c.postJSONAtEndpoint(ctx, path, body, &decoded, endpoint)
			var conflict *ControlPlaneError
			if !errors.As(err, &conflict) || conflict.StatusCode != http.StatusConflict || i == len(limits)-1 {
				break
			}
		}
		if err != nil {
			c.afterCredentialCheck(ctx, lookupHash, err)
			var cp *ControlPlaneError
			if isDialFailure(err) || errors.As(err, &cp) && (cp.StatusCode == http.StatusNotFound || cp.StatusCode == http.StatusMethodNotAllowed || cp.StatusCode >= 500) {
				// A missing endpoint is not a missing authorization. Preserve recovery
				// during mixed router rollout instead of falsely returning a new-job 400.
				unavailable = &ControlPlaneError{Path: path, StatusCode: 503, Type: "video_replay_unavailable", Message: "video replay lookup is temporarily unavailable"}
				continue
			}
			return nil, err
		}
		c.afterCredentialCheck(ctx, lookupHash, nil)
		if decoded.Data.Found == nil {
			return nil, idempotencyReplayConflict()
		}
		if !*decoded.Data.Found {
			if decoded.Data.Authorization != nil {
				return nil, idempotencyReplayConflict()
			}
			continue
		}
		auth := decoded.Data.Authorization
		if auth == nil || !auth.IdempotentReplay {
			return nil, idempotencyReplayConflict()
		}
		var replay *videoReplayLookup
		if !errors.As(videoReplayConflict(body, auth, endpoint), &replay) {
			return nil, idempotencyReplayConflict()
		}
		return c.recoverVideoReplay(ctx, bearer, model, replay)
	}
	return nil, unavailable
}
