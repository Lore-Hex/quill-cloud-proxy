package trustedrouter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Ordered control-plane endpoints, and the rule for when moving to the next one
// is safe.
//
// WHY THIS EXISTS
//
// Authorization is on the request path (cmd/enclave/main.go,
// AuthorizeWithRoute), and an error there ends the request. Deployments
// configure one canonical billing authority. Adding another production
// authority requires a reviewed code and measurement change; public
// observer/status services are not billing authorities and must never appear
// here. The ordered form remains for local failover tests and that future
// explicitly-reviewed deployment.
//
// WHEN FAILOVER IS SAFE — the only interesting question here
//
// These are money operations against SEPARATE databases. A reservation created
// on one plane is invisible to the next, and the idempotency key does not
// travel, so re-sending `authorize` somewhere else can escrow twice and
// re-sending `settle` can bill twice. Failover is therefore permitted ONLY when
// the request provably never reached ANY server.
//
// The dialer is what makes that provable. net/http calls DialContext before it
// writes a single byte of the request, so an error originating there cannot
// have produced a reservation. Everything after — a response, a read timeout, a
// context deadline — is ambiguous: the server may have processed the request and
// we simply did not hear the answer. Those must NOT fail over.
//
// Classifying by error SHAPE was rejected: on AWS the dialer is a vsock dial
// whose failures are plain syscall errors, not *net.OpError, so a shape-based
// check would miss the single most likely real failure (the parent's vsock-proxy
// being down). Instead the dialer itself is wrapped and its errors are tagged,
// which is exact and transport-independent.

// dialFailure marks an error as having come from the dialer, i.e. strictly
// before any request byte was written.
type dialFailure struct{ err error }

func (e *dialFailure) Error() string { return "dial: " + e.err.Error() }
func (e *dialFailure) Unwrap() error { return e.err }

// markDialFailures wraps a transport's DialContext so failures it produces are
// identifiable later. Applied by every newControlPlaneHTTPClient variant.
func markDialFailures(t *http.Transport) *http.Transport {
	inner := t.DialContext
	if inner == nil {
		d := &net.Dialer{}
		inner = d.DialContext
	}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := inner(ctx, network, addr)
		if err != nil {
			return nil, &dialFailure{err: err}
		}
		return conn, nil
	}
	return t
}

// isDialFailure reports whether err was produced by the dialer, and therefore
// whether the request definitely never reached a server.
//
// A cancelled or expired caller context is deliberately excluded even when it
// surfaces through the dialer: the caller is giving up, and trying another
// endpoint would ignore that.
func isDialFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var df *dialFailure
	return errors.As(err, &df)
}

// parseControlPlaneEndpoints splits the configured value into an ordered list.
//
// A single value keeps today's behaviour exactly. A comma-separated list is
// tried in order, so the FIRST entry must be the intended billing authority,
// with later entries used only when an earlier one cannot be dialled at all.
func parseControlPlaneEndpoints(value string) ([]string, error) {
	seen := make(map[string]struct{})
	out := make([]string, 0, 2)
	for _, part := range strings.Split(value, ",") {
		endpoint := strings.TrimRight(strings.TrimSpace(part), "/")
		if endpoint == "" {
			continue
		}
		normalized, err := validateControlPlaneEndpoint(endpoint)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[normalized]; dup {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out, nil
}

type controlPlaneConfigurationError struct {
	endpoint string
	reason   string
}

func (e *controlPlaneConfigurationError) Error() string {
	return fmt.Sprintf("trustedrouter: invalid control-plane endpoint %q: %s", e.endpoint, e.reason)
}

func validateControlPlaneEndpoint(raw string) (string, error) {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return "", &controlPlaneConfigurationError{endpoint: raw, reason: "must be an absolute URL"}
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", &controlPlaneConfigurationError{endpoint: raw, reason: "userinfo, query strings, and fragments are forbidden"}
	}
	if parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
		return "", &controlPlaneConfigurationError{endpoint: raw, reason: "the billing-authority URL must not contain a path (including /v1)"}
	}

	host := strings.ToLower(strings.TrimRight(parsed.Hostname(), "."))
	if host == "" {
		return "", &controlPlaneConfigurationError{endpoint: raw, reason: "hostname is required"}
	}
	port := parsed.Port()
	if host == "trustedrouter.com" {
		if parsed.Scheme != "https" || (port != "" && port != "443") {
			return "", &controlPlaneConfigurationError{endpoint: raw, reason: "the canonical billing authority requires HTTPS on port 443"}
		}
		return "https://trustedrouter.com", nil
	}

	// Loopback is intentionally limited to tests and local development. Any
	// additional production authority requires a reviewed code and measurement
	// change instead of an operator-controlled URL override.
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		return strings.TrimRight(raw, "/"), nil
	}
	if observerOnlyControlPlaneHost(host) {
		return "", &controlPlaneConfigurationError{endpoint: raw, reason: "the host is an observer-only service"}
	}
	return "", &controlPlaneConfigurationError{endpoint: raw, reason: "the host is not a reviewed billing authority"}
}

func observerOnlyControlPlaneHost(host string) bool {
	switch host {
	case "aws.trustedrouter.com",
		"azure.trustedrouter.com",
		"status.trustedrouter.com":
		return true
	default:
		return strings.HasSuffix(host, ".trustedrouter.com") &&
			(strings.HasPrefix(host, "aws-") ||
				strings.HasPrefix(host, "azure-") ||
				strings.HasPrefix(host, "status-"))
	}
}
