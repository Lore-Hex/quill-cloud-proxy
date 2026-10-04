package upstreamerror

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
)

type credentialsKey struct{}
type credentials struct {
	mu     sync.Mutex
	values []string
}

// WithCredentialRedaction scopes credentials to one provider attempt. The
// returned function scrubs the error before fallback tracking or client output
// can retain it, without keeping an unsanitized wrapped error around.
func WithCredentialRedaction(ctx context.Context, values ...string) (context.Context, func(error) error) {
	c := &credentials{values: append([]string(nil), values...)}
	ctx = context.WithValue(ctx, credentialsKey{}, c)
	return ctx, func(err error) error {
		if err == nil {
			return nil
		}
		var response interface{ UpstreamResponse() (int, string) }
		var status int
		var body string
		if errors.As(err, &response) {
			status, body = response.UpstreamResponse()
		} else {
			s := err.Error()
			match := httpPattern.FindStringSubmatchIndex(s)
			if match == nil {
				return err
			}
			status, _ = strconv.Atoi(s[match[2]:match[3]])
			body = s[match[1]:]
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return &Error{Status: status, Body: sanitize(body, c.values...)}
	}
}

// RecordCredential includes runtime credentials (e.g. Vertex OAuth tokens),
// which may not exist in the gateway's invocation options.
func RecordCredential(ctx context.Context, value string) {
	c, _ := ctx.Value(credentialsKey{}).(*credentials)
	if c == nil || value == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values = append(c.values, value)
	if scheme, token, ok := strings.Cut(value, " "); ok && (strings.EqualFold(scheme, "Bearer") || strings.EqualFold(scheme, "Basic")) {
		c.values = append(c.values, strings.TrimSpace(token))
	}
}

func IsCredentialName(name string) bool {
	switch strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name)) {
	case "apikey", "xapikey", "xgoogapikey", "accesstoken", "xaccesstoken", "xauthtoken", "token", "authorization", "proxyauthorization", "password", "secret", "xamzsecuritytoken":
		return true
	}
	return false
}
