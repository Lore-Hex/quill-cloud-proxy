package trustedrouter

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
)

// Ordered control-plane endpoints, and the rule for when moving to the next one
// is safe.
//
// WHY THIS EXISTS
//
// Every enclave — on GCP, AWS and Azure alike — dialled the single canonical
// control plane and failed CLOSED if it was unreachable: authorization is on the
// request path (cmd/enclave/main.go, AuthorizeWithRoute), and an error there
// ends the request. That made every cloud's availability a product of its own
// uptime and the canonical plane's, which is exactly the shared dependency that
// stops per-cloud numbers multiplying.
//
// Each cloud now runs its own control plane, so the fix has two halves: put the
// cloud's OWN plane first, and let it fall through to another one instead of
// dying.
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
// tried in order, so the FIRST entry should be the plane belonging to this
// cloud — that is what removes the cross-cloud dependency on the normal path,
// with later entries serving only as a floor when the local one cannot be
// dialled at all.
func parseControlPlaneEndpoints(value string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 2)
	for _, part := range strings.Split(value, ",") {
		url := strings.TrimRight(strings.TrimSpace(part), "/")
		if url == "" {
			continue
		}
		if _, dup := seen[url]; dup {
			continue
		}
		seen[url] = struct{}{}
		out = append(out, url)
	}
	return out
}
