package trustedrouter

import (
	"context"
	"errors"
	"io"
	"strings"
	"syscall"
	"time"
)

const settlementRetryBudget = 28 * time.Second

// Settlement replays are idempotent only within the original billing authority.
// Freeze the body and endpoint before retrying an ambiguous lost acknowledgement.
func (c *Client) postSettlementJSON(ctx context.Context, auth *Authorization, body any, out any) error {
	endpoint := auth.pinnedControlPlaneEndpoint()
	if endpoint < 0 && len(c.baseURLs) == 1 {
		endpoint = 0
	}
	if endpoint < 0 || strings.TrimSpace(auth.AuthorizationID) == "" {
		_, err := c.postJSONAtEndpoint(ctx, "/internal/gateway/settle", body, out, endpoint)
		return err
	}
	policy := retryPolicy{
		attempts: 3, baseDelay: 250 * time.Millisecond, maxDelay: time.Second,
		totalBudget: settlementRetryBudget, retryable: retryableSettlementError,
	}
	_, err := c.postJSONWithRetryFromEndpoint(ctx, "/internal/gateway/settle", body, out, policy, endpoint)
	return err
}

func retryableSettlementError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if retryableAuthorizationError(err) {
		return true
	}
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
