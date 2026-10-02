package trustedrouter

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/spendlease"
)

// ConfigureSpeculation is boot-only. Off returns before creating any state,
// refresh timer, record queue or serialization.
func (c *Client) ConfigureSpeculation(ctx context.Context, observer shadowobserve.Observer) {
	if c == nil || observer == nil {
		return
	}
	c.shadow = observer
	go c.shadowCall(func() { c.shadow.Run(ctx, c.RefreshShadow) })
}
func (c *Client) Speculation() shadowobserve.Observer {
	if c == nil {
		return nil
	}
	return c.shadow
}
func (c *Client) ShadowLookup(ctx context.Context, bearer string) string {
	return requestLookupHash(ctx, bearer)
}
func (c *Client) RefreshShadow(ctx context.Context, items []shadowobserve.Identity) ([]shadowobserve.Result, *shadowobserve.Miss) {
	body, m := shadowobserve.EncodeBatch(items)
	if m != nil {
		return nil, m
	}
	signer := c.shadowSigner
	if signer == nil {
		signer = c.stageDBootDigestSigner()
	}
	if signer == nil {
		return nil, &shadowobserve.Miss{Status: 0, Code: "boot-unavailable"}
	}
	proof, err := spendlease.SignAuthorize(signer, http.MethodPost, shadowobserve.RefreshPath, body)
	if err != nil {
		return nil, &shadowobserve.Miss{Status: 0, Code: "boot-unavailable"}
	}
	resp, _, err := c.postToControlPlaneWithBootAuth(ctx, shadowobserve.RefreshPath, body, -1, proof.HeaderValue())
	if err != nil {
		return nil, &shadowobserve.Miss{Status: 0, Code: "transport-unavailable"}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, shadowobserve.MaxResponseBytes+1))
	if err != nil {
		return nil, &shadowobserve.Miss{Status: resp.StatusCode, Code: "malformed-response"}
	}
	return shadowobserve.DecodeBatch(resp.StatusCode, raw, items)
}

type shadowLookupKey struct{}
type shadowCallerKey struct{}

func (c *Client) observeShadowAuthorize(ctx context.Context, lookup string) (context.Context, func(*Authorization, error)) {
	if c.shadow == nil {
		return ctx, nil
	}
	if explicitAuthorizationInvocation(ctx) == nil {
		ctx = WithAuthorizationInvocation(ctx)
	}
	x := shadowobserve.FromContext(ctx)
	if x == nil {
		c.shadowCall(func() { x = c.shadow.Excluded(lookup) })
		ctx = shadowobserve.WithExecution(ctx, x)
	}
	ctx = context.WithValue(ctx, shadowCallerKey{}, ctx)
	ctx = context.WithValue(ctx, shadowLookupKey{}, lookup)
	nonce, _ := authorizationInvocationFromContext(ctx).invocationNonce()
	x.StartAuthorize(nonce, requestLogIDFromContext(ctx))
	return ctx, func(a *Authorization, err error) {
		status, reason := shadowErrorForCaller(ctx, err)
		id := ""
		if err == nil && a != nil {
			id = a.AuthorizationID
			c.shadowCall(func() {
				c.shadow.ObserveAuthorized(shadowobserve.Identity{KeyID: a.APIKeyHash, LookupDigest: lookup, WorkspaceID: a.WorkspaceID})
			})
		} else if status != 0 {
			c.shadowCall(func() {
				var e *ControlPlaneError
				if resolved, ok := c.shadow.(interface {
					ObserveResolvedVerdict(string, int, string, string, shadowobserve.Identity)
				}); ok && errors.As(err, &e) {
					resolved.ObserveResolvedVerdict(lookup, status, reason, e.RateScope, e.ShadowScope)
				} else {
					c.shadow.ObserveVerdict(lookup, status, reason, "")
				}
			})
		}
		x.EndAuthorize(id, status)
		// Excluded authorize entry points have no outer execution owner.
		if x != nil && !x.Decision().Eligible {
			x.Finish()
		}
	}
}
func shadowError(err error) (int, string) {
	if err == nil {
		return 200, ""
	}
	var e *ControlPlaneError
	if errors.As(err, &e) {
		reason := e.Reason
		if reason == "" {
			switch {
			case e.StatusCode == 401 && e.Type == "invalid_api_key":
				reason = "key_invalid"
			case e.StatusCode == 402 && e.Type == "key_limit_exceeded":
				reason = "key_limit_exceeded"
			case e.StatusCode == 429 && e.Type == "key_window_limit_exceeded":
				reason = "key_window_limit_exceeded"
			}
		}
		return e.StatusCode, reason
	}
	return 503, "transport_error"
}

type shadowAttempt struct{ timing *shadowobserve.RouterTiming }
type shadowAttemptKey struct{}

func shadowAttemptFromContext(ctx context.Context) *shadowAttempt {
	s, _ := ctx.Value(shadowAttemptKey{}).(*shadowAttempt)
	return s
}
func (c *Client) beginShadowAttempt(ctx context.Context, path string) (context.Context, func(error, bool)) {
	if c.shadow == nil || path != spendlease.AuthorizePath {
		return ctx, nil
	}
	x := shadowobserve.FromContext(ctx)
	if x == nil {
		return ctx, nil
	}
	start := x.Now()
	sample := &shadowAttempt{}
	return context.WithValue(ctx, shadowAttemptKey{}, sample), func(err error, retryable bool) {
		status, _ := shadowErrorForCaller(ctx, err)
		x.ObserveAttempt(start, status, sample.timing)
		if err != nil && retryable && status >= 500 {
			lookup, _ := ctx.Value(shadowLookupKey{}).(string)
			c.shadowCall(func() { c.shadow.ObserveVerdict(lookup, 503, "infrastructure_error", "") })
		}
	}
}

// Only enabled shadow authorize reads are copied, bounded and immediately
// reduced to typed timing. Existing decode and error-body limits are unchanged.
type shadowTimingBody struct {
	io.ReadCloser
	sample   *shadowAttempt
	raw      []byte
	overflow bool
}

func (b *shadowTimingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if !b.overflow {
		if len(b.raw)+n > 1<<20 {
			b.overflow = true
			b.raw = nil
		} else {
			b.raw = append(b.raw, p[:n]...)
		}
	}
	return n, err
}
func (b *shadowTimingBody) Close() error {
	if !b.overflow {
		b.sample.timing = shadowobserve.DecodeTiming(b.raw)
	}
	b.raw = nil
	return b.ReadCloser.Close()
}

// ConfigureShadowBoot signs refresh only, preserving ordinary authorize headers.
func (c *Client) ConfigureShadowBoot(signer spendlease.DigestSigner) {
	if c != nil {
		c.shadowSigner = signer
	}
}
func (c *Client) Fault() {
	c.shadowBoundary.Fault()
	if host, ok := c.shadow.(interface{ Fault() }); ok {
		shadowobserve.Protect(&c.shadowBoundary, host.Fault)
	}
}
func (c *Client) shadowCall(callback func()) {
	if c.shadowBoundary.Failures() == 0 {
		shadowobserve.Protect(c, callback)
	}
}
func (c *Client) ShadowFailures() uint64 { return c.shadowBoundary.Failures() }
func (c *Client) ObserveShadowSuppressed(id string) {
	if c != nil && c.shadow != nil {
		c.shadowCall(func() { c.shadow.Suppressed(id) })
	}
}

// The caller is captured before the retry loop creates its own budget context.
// A retry-budget/transport timeout with a live caller is infrastructure evidence.
func shadowErrorForCaller(ctx context.Context, err error) (int, string) {
	caller, _ := ctx.Value(shadowCallerKey{}).(context.Context)
	if caller == nil {
		caller = ctx
	}
	if caller.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return 0, "caller-canceled"
	}
	return shadowError(err)
}
