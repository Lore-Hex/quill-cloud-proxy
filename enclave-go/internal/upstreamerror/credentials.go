package upstreamerror

import (
	"context"
	"errors"
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
		status, body, ok := responseBody(err)
		if !ok {
			return err
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return preserveMarkers(err, &Error{Status: status, Body: sanitize(body, c.values...)}, c.values...)
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

// clientInputMarker is how the gateway marks a failure as the caller's input
// (cmd/enclave's clientInputError), not the provider's.
type clientInputMarker interface {
	ClientInputMessage() string
}

// clientInput keeps a caller-input marker on a redacted error.
type clientInput struct {
	err     error
	message string
}

func (e *clientInput) Error() string              { return e.err.Error() }
func (e *clientInput) Unwrap() error              { return e.err }
func (e *clientInput) ClientInputMessage() string { return e.message }

// preserveMarkers re-applies the original error's classification markers to
// its redacted replacement. Redaction rebuilds the error so no unsanitized
// body survives in its chain; without this it would also drop what the
// gateway knows about it (caller input, the gateway's own failure), and a
// caller-input or local failure carrying an HTTP status would be read as the
// provider failing.
func preserveMarkers(original, redacted error, secrets ...string) error {
	out := redacted
	var input clientInputMarker
	if errors.As(original, &input) {
		out = &clientInput{err: out, message: sanitizeText(input.ClientInputMessage(), secrets...)}
	}
	if IsLocal(original) {
		out = &Local{Err: out}
	}
	return out
}
