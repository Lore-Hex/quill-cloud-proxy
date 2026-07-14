package trustedrouter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAuthorizeAttempts  = 3
	defaultAuthorizeBaseDelay = 500 * time.Millisecond
	defaultAuthorizeMaxDelay  = 4 * time.Second
	// A control-plane transaction has a 20-second wall-clock budget. Bound
	// the complete retry loop below the old 30-second per-attempt HTTP timeout
	// so retries cannot amplify one contention event into a minute-long stall.
	defaultAuthorizeBudget = 28 * time.Second
)

type retryPolicy struct {
	attempts    int
	baseDelay   time.Duration
	maxDelay    time.Duration
	totalBudget time.Duration
	sleep       func(context.Context, time.Duration) error
}

func defaultAuthorizeRetryPolicy() retryPolicy {
	return retryPolicy{
		attempts:    defaultAuthorizeAttempts,
		baseDelay:   defaultAuthorizeBaseDelay,
		maxDelay:    defaultAuthorizeMaxDelay,
		totalBudget: defaultAuthorizeBudget,
		sleep:       sleepContext,
	}
}

func authorizationIdempotencyKey(candidate string) (string, error) {
	if candidate = strings.TrimSpace(candidate); candidate != "" {
		return candidate, nil
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("trustedrouter: generate authorization idempotency key: %w", err)
	}
	return "tr-gateway-" + hex.EncodeToString(random[:]), nil
}

func (c *Client) postJSONWithRetry(
	ctx context.Context,
	path string,
	payload any,
	out any,
	policy retryPolicy,
) error {
	retryCtx := ctx
	cancel := func() {}
	if policy.totalBudget > 0 {
		retryCtx, cancel = context.WithTimeout(ctx, policy.totalBudget)
	}
	defer cancel()

	policy = normalizeRetryPolicy(policy)
	var lastRetryableErr error
	for attempt := 1; attempt <= policy.attempts; attempt++ {
		err := c.postJSON(retryCtx, path, payload, out)
		if err == nil {
			return nil
		}
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil && lastRetryableErr != nil {
			return lastRetryableErr
		}
		if attempt == policy.attempts || !retryableAuthorizationError(err) {
			return err
		}
		lastRetryableErr = err

		delay := authorizationRetryDelay(attempt, policy, retryAfterDuration(err))
		status := 0
		var controlErr *ControlPlaneError
		if errors.As(err, &controlErr) {
			status = controlErr.StatusCode
		}
		fmt.Fprintf(os.Stderr,
			"enclave.control_plane_retry path=%q status=%d attempt=%d next_attempt=%d delay_ms=%d\n",
			path,
			status,
			attempt,
			attempt+1,
			delay.Milliseconds(),
		)
		if err := policy.sleep(retryCtx, delay); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return lastRetryableErr
		}
	}
	return fmt.Errorf("trustedrouter: retry loop exhausted")
}

func normalizeRetryPolicy(policy retryPolicy) retryPolicy {
	if policy.attempts < 1 {
		policy.attempts = 1
	}
	policy.baseDelay = max(policy.baseDelay, 0)
	policy.maxDelay = max(policy.maxDelay, 0)
	if policy.maxDelay > 0 {
		policy.baseDelay = min(policy.baseDelay, policy.maxDelay)
	}
	if policy.sleep == nil {
		policy.sleep = sleepContext
	}
	return policy
}

func retryableAuthorizationError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var controlErr *ControlPlaneError
	if !errors.As(err, &controlErr) {
		return false
	}
	switch controlErr.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func retryAfterDuration(err error) time.Duration {
	var controlErr *ControlPlaneError
	if !errors.As(err, &controlErr) || controlErr.RetryAfter == "" {
		return 0
	}
	seconds, parseErr := strconv.ParseInt(controlErr.RetryAfter, 10, 32)
	if parseErr != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func authorizationRetryDelay(failedAttempt int, policy retryPolicy, retryAfter time.Duration) time.Duration {
	failedAttempt = max(failedAttempt, 1)
	if policy.maxDelay <= 0 {
		return 0
	}
	floor := min(retryAfter, policy.maxDelay)
	ceiling := max(policy.baseDelay, floor)
	for attempt := 1; attempt < failedAttempt && ceiling < policy.maxDelay; attempt++ {
		if ceiling > policy.maxDelay/2 {
			ceiling = policy.maxDelay
			break
		}
		ceiling *= 2
	}
	ceiling = min(ceiling, policy.maxDelay)
	if ceiling <= floor {
		return floor
	}
	return floor + fullJitter(ceiling-floor)
}

func fullJitter(ceiling time.Duration) time.Duration {
	if ceiling <= 0 {
		return 0
	}
	random, err := rand.Int(rand.Reader, big.NewInt(int64(ceiling)+1))
	if err != nil {
		return ceiling / 2
	}
	return time.Duration(random.Int64())
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
