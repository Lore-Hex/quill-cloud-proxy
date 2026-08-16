package llm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// IPResolver is the DNS surface used by the guarded dialer. It is injectable
// so the mixed-answer fail-closed rule can be tested without trusting the
// machine running the test.
type IPResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// EgressGuardOptions configures one owner-dispatch transport. The client is
// deliberately per request: owner hosts are untrusted and must never share a
// proxy, connection pool, redirect policy, or timeout with ordinary providers.
type EgressGuardOptions struct {
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	IdleTimeout           time.Duration
	TotalTimeout          time.Duration
	Resolver              IPResolver
	DialContext           func(context.Context, string, string) (net.Conn, error)
	RootCAs               *x509.CertPool
}

// EgressGuardError means DNS resolution or the public-address policy refused
// the connection before any owner request bytes were sent.
type EgressGuardError struct {
	Reason string
}

func (e *EgressGuardError) Error() string {
	if e == nil || e.Reason == "" {
		return "llm/egress-guard: connection refused"
	}
	return "llm/egress-guard: " + e.Reason
}

// EgressDialError distinguishes a connection-budget failure from the owner's
// first-byte budget. The dispatcher's strike taxonomy treats both as owner
// faults, but callers and the control plane need the honest failure class.
type EgressDialError struct {
	Err error
}

func (e *EgressDialError) Error() string {
	return "llm/egress-guard: dial vetted address: " + e.Err.Error()
}

func (e *EgressDialError) Unwrap() error { return e.Err }

// NewGuardedHTTPClient returns a no-proxy, no-redirect HTTPS client pinned to
// DNS answers that were all proven public. DialTLSContext stays unset on
// purpose: net/http performs TLS against the URL hostname, preserving SNI and
// certificate verification while DialContext connects to the vetted IP.
func NewGuardedHTTPClient(endpointURL string, options EgressGuardOptions) (*http.Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpointURL))
	if err != nil {
		return nil, &EgressGuardError{Reason: "invalid endpoint URL"}
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return nil, &EgressGuardError{Reason: "endpoint must use https"}
	}
	registeredHost := strings.TrimSpace(parsed.Hostname())
	if registeredHost == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, &EgressGuardError{Reason: "invalid endpoint URL"}
	}
	registeredHost, err = canonicalEgressHost(registeredHost)
	if err != nil {
		return nil, err
	}
	if isTrustedRouterEgressHost(registeredHost) {
		// The enclave must enforce this independently of registration so a stale
		// control-plane row cannot recurse back into a TrustedRouter gateway.
		return nil, &EgressGuardError{Reason: "endpoint must not be a TrustedRouter host"}
	}

	connectTimeout := options.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}
	resolver := options.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dial := options.DialContext
	if dial == nil {
		networkDialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
		dial = networkDialer.DialContext
	}

	guardedDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, &EgressGuardError{Reason: "invalid dial address"}
		}
		dialHost, normalizeErr := canonicalEgressHost(host)
		if normalizeErr != nil || !strings.EqualFold(dialHost, registeredHost) {
			return nil, &EgressGuardError{Reason: "dial host differs from registered host"}
		}
		// DNS is part of connection establishment. A hostile or broken
		// nameserver must not stretch a 10-second connect budget to the longer
		// first-byte allowance.
		connectCtx, cancel := context.WithTimeout(ctx, connectTimeout)
		defer cancel()
		addresses, resolveErr := resolveAll(connectCtx, resolver, registeredHost)
		if resolveErr != nil {
			return nil, resolveErr
		}
		for _, address := range addresses {
			if !allowedPublicIP(address) {
				return nil, &EgressGuardError{Reason: "DNS answer is not public"}
			}
		}
		if len(addresses) == 0 {
			return nil, &EgressGuardError{Reason: "DNS returned no addresses"}
		}

		var lastDialErr error
		for _, vettedAddress := range addresses {
			// All answers were vetted before the first dial. Trying them in DNS
			// order preserves fail-closed mixed-answer handling while avoiding an
			// outage when the first public address alone is unreachable.
			conn, dialErr := dial(connectCtx, network, net.JoinHostPort(vettedAddress.Unmap().String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastDialErr = dialErr
		}
		return nil, &EgressDialError{Err: lastDialErr}
	}

	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       guardedDial,
		ForceAttemptHTTP2: true,
		// Owner responses are deliberately small. Transparent gzip inflation is
		// an unnecessary memory amplifier at this untrusted boundary.
		DisableCompression:    true,
		ResponseHeaderTimeout: options.ResponseHeaderTimeout,
		TLSHandshakeTimeout:   connectTimeout,
		IdleConnTimeout:       options.IdleTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    options.RootCAs,
		},
	}
	return &http.Client{
		Transport: &idleBodyTransport{base: transport, timeout: options.IdleTimeout},
		Timeout:   options.TotalTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func canonicalEgressHost(host string) (string, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return "", &EgressGuardError{Reason: "invalid endpoint host"}
	}
	if address, parseErr := netip.ParseAddr(strings.Trim(host, "[]")); parseErr == nil {
		return strings.ToLower(address.Unmap().String()), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" {
		return "", &EgressGuardError{Reason: "invalid endpoint host"}
	}
	return strings.ToLower(strings.TrimSuffix(ascii, ".")), nil
}

var trustedRouterEgressSuffixes = [...]string{
	"trustedrouter.com",
	"allyrouter.com",
	"uptimerouter.com",
}

func isTrustedRouterEgressHost(host string) bool {
	for _, suffix := range trustedRouterEgressSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func resolveAll(ctx context.Context, resolver IPResolver, host string) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{literal}, nil
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, &EgressGuardError{Reason: "DNS resolution failed"}
	}
	return addresses, nil
}

func allowedPublicIP(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	address = address.Unmap()
	if address.IsLoopback() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	if address.Is6() && !globalIPv6Unicast.Contains(address) {
		// IANA's globally allocated IPv6 unicast space is 2000::/3. Go's
		// IsGlobalUnicast also returns true for unallocated/reserved ranges;
		// safe_egress.py rejects those through ipaddress.is_reserved.
		return false
	}
	for _, prefix := range publicEgressExceptions {
		if prefix.Contains(address) {
			return true
		}
	}
	if address.IsPrivate() {
		return false
	}
	// Go's IsPrivate intentionally covers only RFC 1918/4193. The control
	// plane also rejects reserved/documentation/benchmark ranges; enumerate
	// them so both halves make the same decision instead of relying on
	// IsGlobalUnicast (which considers several private ranges global-unicast).
	for _, prefix := range reservedEgressPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var globalIPv6Unicast = netip.MustParsePrefix("2000::/3")

var reservedEgressPrefixes = mustEgressPrefixes(
	"0.0.0.0/8",
	// Shared address space (CGNAT, RFC 6598): never internet-routable, and
	// used INSIDE clouds for internal services — an owner "endpoint" there
	// is an internal target, not a public one.
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"100::/64",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"3fff::/20",
)

var publicEgressExceptions = mustEgressPrefixes(
	"192.0.0.9/32",
	"192.0.0.10/32",
	"2001:1::1/128",
	"2001:1::2/128",
	"2001:3::/32",
	"2001:4:112::/48",
	"2001:20::/28",
	"2001:30::/28",
)

func mustEgressPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

type idleBodyTransport struct {
	base    http.RoundTripper
	timeout time.Duration
}

func (t *idleBodyTransport) CloseIdleConnections() {
	// http.Client only discovers pool cleanup through this optional method;
	// without forwarding it, every per-dispatch owner Transport leaked its idle
	// sockets until the transport's timeout elapsed.
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t *idleBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(req)
	if err != nil || response == nil || response.Body == nil || t.timeout <= 0 {
		return response, err
	}
	response.Body = &idleTimeoutBody{ReadCloser: response.Body, timeout: t.timeout, firstRead: true}
	return response, nil
}

type idleTimeoutBody struct {
	io.ReadCloser
	timeout   time.Duration
	firstRead bool
}

func (b *idleTimeoutBody) Read(p []byte) (int, error) {
	if b.firstRead {
		b.firstRead = false
		return b.ReadCloser.Read(p)
	}
	buffer := make([]byte, len(p))
	result := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := b.ReadCloser.Read(buffer)
		result <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()
	timer := time.NewTimer(b.timeout)
	defer timer.Stop()
	select {
	case completed := <-result:
		copy(p, buffer[:completed.n])
		return completed.n, completed.err
	case <-timer.C:
		_ = b.ReadCloser.Close()
		return 0, &egressIdleTimeoutError{}
	}
}

type egressIdleTimeoutError struct{}

func (*egressIdleTimeoutError) Error() string   { return "llm/egress-guard: idle budget exceeded" }
func (*egressIdleTimeoutError) Timeout() bool   { return true }
func (*egressIdleTimeoutError) Temporary() bool { return true }
