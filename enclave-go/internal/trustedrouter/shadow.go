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
	go c.shadow.Run(ctx, c.RefreshShadow)
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
	signer := c.stageDBootDigestSigner()
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

func (c *Client) observeShadowAuthorize(ctx context.Context, lookup string) (context.Context, func(*Authorization, error)) {
	if c.shadow == nil {
		return ctx, nil
	}
	if explicitAuthorizationInvocation(ctx) == nil {
		ctx = WithAuthorizationInvocation(ctx)
	}
	x := shadowobserve.FromContext(ctx)
	if x == nil {
		x = c.shadow.Excluded(lookup)
		ctx = shadowobserve.WithExecution(ctx, x)
	}
	ctx = context.WithValue(ctx, shadowLookupKey{}, lookup)
	nonce, _ := authorizationInvocationFromContext(ctx).invocationNonce()
	x.StartAuthorize(nonce, requestLogIDFromContext(ctx))
	return ctx, func(a *Authorization, err error) {
		id := ""
		if err == nil && a != nil {
			id = a.AuthorizationID
			c.shadow.ObserveAuthorized(shadowobserve.Identity{KeyID: a.APIKeyHash, LookupDigest: lookup, WorkspaceID: a.WorkspaceID})
		} else {
			status, reason := shadowError(err)
			c.shadow.ObserveVerdict(lookup, status, reason, "")
		}
		status, _ := shadowError(err)
		x.EndAuthorize(id, status)
		// Excluded authorize entry points have no outer execution owner.
		if !x.Decision().Eligible {
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
		status, _ := shadowError(err)
		x.ObserveAttempt(start, status, sample.timing)
		if err != nil && retryable {
			lookup, _ := ctx.Value(shadowLookupKey{}).(string)
			c.shadow.ObserveVerdict(lookup, 503, "infrastructure_error", "")
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
