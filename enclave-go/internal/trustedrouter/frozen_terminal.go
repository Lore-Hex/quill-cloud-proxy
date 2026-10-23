package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	settlePath = "/internal/gateway/settle"
	refundPath = "/internal/gateway/refund"
)

// FrozenTerminal is a settle or refund fixed at the moment it was built: the
// path, the exact body bytes, and the billing authority that holds the
// authorization. A replay sends the same bytes to the same authority and
// rebuilds nothing from request state, which is what keeps it idempotent at the
// router.
//
// BaseURL is empty when the authorization was never pinned and the client has
// several authorities; the replay then goes to the first dialable one, as the
// original send did. BootAuth is sent as the boot-auth header when set. Settles
// and refunds are not boot-signed today, so it is empty for them.
type FrozenTerminal struct {
	Path     string
	Body     []byte
	BaseURL  string
	BootAuth string
}

var errNilClient = errors.New("trustedrouter: nil client")

// FreezeSettle freezes the settle Settle would send for auth and usage without
// async or shadow settlement. The request log id and client context are read
// from ctx.
func (c *Client) FreezeSettle(ctx context.Context, auth *Authorization, usage Usage) (*FrozenTerminal, error) {
	if auth == nil {
		return nil, fmt.Errorf("trustedrouter: nil authorization")
	}
	if c == nil {
		return nil, errNilClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	baseURL, err := c.frozenAuthority(c.settlementEndpoint(auth))
	if err != nil {
		return nil, err
	}
	body, err := buildSettleBody(ctx, auth, usage)
	if err != nil {
		return nil, err
	}
	return &FrozenTerminal{Path: settlePath, Body: body, BaseURL: baseURL}, nil
}

// FreezeRefund freezes the refund RefundDetailed would send. A nil
// authorization has no hold to close: it returns nil and no error, and nothing
// is to be sent.
func (c *Client) FreezeRefund(
	ctx context.Context,
	auth *Authorization,
	status int,
	errorType string,
	elapsedSeconds float64,
	metadata map[string]any,
) (*FrozenTerminal, error) {
	if auth == nil {
		return nil, nil
	}
	if c == nil {
		return nil, errNilClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	baseURL, err := c.frozenAuthority(auth.pinnedControlPlaneEndpoint())
	if err != nil {
		return nil, err
	}
	body, err := buildRefundBody(ctx, auth, status, errorType, elapsedSeconds, metadata, RefundAttribution{})
	if err != nil {
		return nil, err
	}
	return &FrozenTerminal{Path: refundPath, Body: body, BaseURL: baseURL}, nil
}

// PostFrozenTerminal sends t with the policy of the original send. A settle at a
// known authority for a named authorization is retried within
// settlementRetryBudget, every attempt at that authority; a refund is sent once
// with its own deadline, whatever has happened to ctx. Async and shadow
// settlement headers are never sent: a replay carries only its frozen bytes.
func (c *Client) PostFrozenTerminal(ctx context.Context, t FrozenTerminal) (*SettleResult, error) {
	if c == nil {
		return nil, errNilClient
	}
	if c.configurationError != nil {
		return nil, c.configurationError
	}
	endpoint, err := c.frozenEndpoint(t.BaseURL)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, asyncModeKey{}, "")
	ctx = context.WithValue(ctx, shadowHeaderKey{}, "")
	switch t.Path {
	case settlePath:
		var decoded struct {
			Data SettleResult `json:"data"`
		}
		if err := c.postSettlement(ctx, endpoint, frozenAuthorizationID(t.Body), t.Body, t.BootAuth, &decoded); err != nil {
			return nil, err
		}
		return &decoded.Data, nil
	case refundPath:
		return c.postRefund(ctx, endpoint, t.Body, t.BootAuth)
	default:
		return nil, fmt.Errorf("trustedrouter: frozen terminal path %q is not a settle or refund", t.Path)
	}
}

// frozenAuthority names the authority at endpoint. An index this client cannot
// resolve fails here with the error the send would have returned; when the
// client has no usable authority the send reports that instead, as before.
func (c *Client) frozenAuthority(endpoint int) (string, error) {
	switch {
	case endpoint < 0:
		return "", nil
	case endpoint < len(c.baseURLs):
		return c.baseURLs[endpoint], nil
	case c.configurationError != nil || len(c.baseURLs) == 0:
		return "", nil
	default:
		return "", fmt.Errorf("trustedrouter: invalid control-plane endpoint index %d", endpoint)
	}
}

func (c *Client) frozenEndpoint(baseURL string) (int, error) {
	if baseURL == "" {
		return -1, nil
	}
	for i, configured := range c.baseURLs {
		if configured == baseURL {
			return i, nil
		}
	}
	return -1, fmt.Errorf("trustedrouter: frozen terminal authority %q is not configured", baseURL)
}

// frozenAuthorizationID reads the authorization a frozen settle names, which
// decides whether it may be retried (see postSettlement).
func frozenAuthorizationID(body []byte) string {
	var fields struct {
		AuthorizationID string `json:"authorization_id"`
	}
	if json.Unmarshal(body, &fields) != nil {
		return ""
	}
	return fields.AuthorizationID
}
