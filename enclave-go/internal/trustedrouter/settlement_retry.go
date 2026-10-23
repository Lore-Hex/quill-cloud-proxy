package trustedrouter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"syscall"
	"time"
)

const settlementRetryBudget = 28 * time.Second

// Settlement replays are idempotent only within the original billing authority.
// Freeze the body and endpoint before retrying an ambiguous lost acknowledgement.
func (c *Client) postSettlementJSON(ctx context.Context, auth *Authorization, body []byte, out any) error {
	return c.postSettlement(ctx, c.settlementEndpoint(auth), auth.AuthorizationID, body, "", out)
}

// settlementEndpoint is the authority a settle for auth goes to: the one that
// created its hold, or the only one configured. -1 means the first dialable.
func (c *Client) settlementEndpoint(auth *Authorization) int {
	endpoint := auth.pinnedControlPlaneEndpoint()
	if endpoint < 0 && len(c.baseURLs) == 1 {
		endpoint = 0
	}
	return endpoint
}

// postSettlement sends settle bytes. At a known authority, for a named
// authorization, it retries ambiguous failures within settlementRetryBudget,
// always at that authority; otherwise it sends once.
func (c *Client) postSettlement(ctx context.Context, endpoint int, authorizationID string, body []byte, bootAuth string, out any) error {
	if endpoint < 0 || strings.TrimSpace(authorizationID) == "" {
		_, err := c.postJSONBytesWithBootAuthAtEndpoint(ctx, settlePath, body, out, endpoint, bootAuth)
		return err
	}
	policy := retryPolicy{
		attempts: 3, baseDelay: 250 * time.Millisecond, maxDelay: time.Second,
		totalBudget: settlementRetryBudget, retryable: retryableSettlementError,
	}
	_, err := c.postJSONBytesWithRetryFromEndpoint(ctx, settlePath, body, out, policy, endpoint, bootAuth)
	return err
}

func retryableSettlementError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var controlErr *ControlPlaneError
	if errors.As(err, &controlErr) {
		// A retiring proxy can return 5xx even when the settlement committed.
		// Replay only the frozen body at its pinned authority, never inference.
		switch controlErr.StatusCode {
		case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		default:
			return false
		}
	}
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
