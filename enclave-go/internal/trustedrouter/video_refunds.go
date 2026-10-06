package trustedrouter

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
)

// Keep only billing identity, never provider credentials or request content.
// A failed attempt stays registered until the pinned authority acknowledges it.
// Both a caller retry and the video worker can drain the same obligation.
type videoRoutingRefund struct {
	mu      sync.Mutex
	auth    Authorization
	request [32]byte
	done    bool
}

type videoRefundID struct {
	authorization string
	endpoint      int
}

func videoRefundRequest(ctx context.Context, bearer, model, key, fingerprint string) [32]byte {
	body, _ := json.Marshal([]string{requestLookupHash(ctx, bearer), model, key, fingerprint})
	return sha256.Sum256(body)
}

// This marker distinguishes the local seed guard from ordinary router errors,
// whose public response bytes (including unseeded errors) must remain unchanged.
type videoRoutingConstraintError struct{ cause *ControlPlaneError }

func (e *videoRoutingConstraintError) Error() string { return e.cause.Error() }
func (e *videoRoutingConstraintError) Unwrap() error { return e.cause }

func IsVideoRoutingUnavailable(err error) bool {
	var routing *videoRoutingConstraintError
	return errors.As(err, &routing)
}

func videoRoutingUnavailable() error {
	return &videoRoutingConstraintError{cause: &ControlPlaneError{Path: "/internal/gateway/authorize", StatusCode: 503,
		Type:    "video_routing_unavailable",
		Message: "control plane returned a video route outside the required provider constraints"}}
}

func (c *Client) rememberVideoRefund(auth *Authorization, request [32]byte) *videoRoutingRefund {
	id := videoRefundID{auth.AuthorizationID, auth.pinnedControlPlaneEndpoint()}
	c.videoRefundsMu.Lock()
	defer c.videoRefundsMu.Unlock()
	if c.videoRefunds == nil {
		c.videoRefunds = make(map[videoRefundID]*videoRoutingRefund)
	}
	if pending := c.videoRefunds[id]; pending != nil {
		return pending
	}
	pending := &videoRoutingRefund{request: request, auth: Authorization{
		AuthorizationID: auth.AuthorizationID, Model: auth.Model, EndpointID: auth.EndpointID,
		RouteType: auth.RouteType, ControlPlaneEndpoint: auth.ControlPlaneEndpoint,
		ControlPlaneEndpointSet: auth.ControlPlaneEndpointSet,
	}}
	c.videoRefunds[id] = pending
	return pending
}

func (c *Client) retryVideoRefund(ctx context.Context, pending *videoRoutingRefund) error {
	pending.mu.Lock()
	defer pending.mu.Unlock()
	if pending.done {
		return nil
	}
	if err := c.Refund(ctx, &pending.auth, 503, "video_routing_unavailable", 0.001, nil); err != nil {
		return err
	}
	pending.done = true
	c.videoRefundsMu.Lock()
	delete(c.videoRefunds, videoRefundID{pending.auth.AuthorizationID, pending.auth.pinnedControlPlaneEndpoint()})
	c.videoRefundsMu.Unlock()
	return nil
}

func (c *Client) pendingVideoRefund(request [32]byte) *videoRoutingRefund {
	c.videoRefundsMu.Lock()
	defer c.videoRefundsMu.Unlock()
	for _, pending := range c.videoRefunds {
		if pending.request == request {
			return pending
		}
	}
	return nil
}

// RetryVideoRoutingRefunds releases rejected video holds even if the caller
// never retries. Errors retain the obligation for the next worker pass.
func (c *Client) RetryVideoRoutingRefunds(ctx context.Context) error {
	c.videoRefundsMu.Lock()
	pending := make([]*videoRoutingRefund, 0, len(c.videoRefunds))
	for _, refund := range c.videoRefunds {
		pending = append(pending, refund)
	}
	c.videoRefundsMu.Unlock()
	var errs []error
	for _, refund := range pending {
		if err := c.retryVideoRefund(ctx, refund); err != nil {
			errs = append(errs, err)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return errors.Join(errs...)
}
