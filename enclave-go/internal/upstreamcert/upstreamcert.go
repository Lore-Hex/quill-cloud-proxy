// Package upstreamcert attributes WebPKI leaf certificates to the exact
// pooled connection used by an HTTP request.
package upstreamcert

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

var rawBase64URL = base64.RawURLEncoding

type contextKey struct{}

type carrier struct {
	mu        sync.RWMutex
	cert      string
	epoch     uint64
	active    int
	ambiguous bool
}

// WithCarrier installs the request-scoped mutable attribution carrier. An
// existing carrier is retained so derived provider contexts report back to the
// serving goroutine.
func WithCarrier(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if currentCarrier(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, &carrier{})
}

// Reset clears attribution between provider fallback attempts and invalidates
// any in-flight attribution handle from an earlier attempt.
func Reset(ctx context.Context) {
	c := currentCarrier(ctx)
	if c == nil {
		return
	}
	c.mu.Lock()
	c.cert = ""
	c.epoch++
	c.active = 0
	c.ambiguous = false
	c.mu.Unlock()
}

// FromContext returns a fingerprint only after certain attribution completed.
func FromContext(ctx context.Context) (string, bool) {
	c := currentCarrier(ctx)
	if c == nil {
		return "", false
	}
	c.mu.RLock()
	cert := c.cert
	c.mu.RUnlock()
	return cert, cert != ""
}

func currentCarrier(ctx context.Context) *carrier {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(contextKey{}).(*carrier)
	return c
}

type attribution struct {
	carrier *carrier
	epoch   uint64
}

func begin(ctx context.Context) (attribution, bool) {
	c := currentCarrier(ctx)
	if c == nil {
		return attribution{}, false
	}
	c.mu.Lock()
	if c.active == 0 {
		c.ambiguous = false
	} else {
		c.ambiguous = true
	}
	c.active++
	c.cert = ""
	a := attribution{carrier: c, epoch: c.epoch}
	c.mu.Unlock()
	return a, true
}

func (a attribution) finish(cert string, certain bool) bool {
	c := a.carrier
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if a.epoch != c.epoch || c.active == 0 {
		return false
	}
	if !certain || cert == "" {
		c.ambiguous = true
	}
	c.active--
	if c.active != 0 {
		return false
	}
	if c.ambiguous {
		c.cert = ""
		return false
	}
	c.cert = cert
	return true
}

// Registry binds the identity returned by httptrace.GotConn to the leaf
// certificate observed when that TLS connection was established.
type Registry struct {
	fingerprints sync.Map // map[net.Conn]string
}

// Record stores the unpadded base64url SHA-256 fingerprint of leafDER.
func (r *Registry) Record(conn net.Conn, leafDER []byte) {
	if r == nil || conn == nil || len(leafDER) == 0 {
		return
	}
	digest := sha256.Sum256(leafDER)
	r.fingerprints.Store(conn, rawBase64URL.EncodeToString(digest[:]))
}

// Delete removes a closed connection from the registry.
func (r *Registry) Delete(conn net.Conn) {
	if r != nil && conn != nil {
		r.fingerprints.Delete(conn)
	}
}

// Lookup resolves the exact connection identity reported by GotConn.
func (r *Registry) Lookup(conn net.Conn) (string, bool) {
	if r == nil || conn == nil {
		return "", false
	}
	value, ok := r.fingerprints.Load(conn)
	if !ok {
		return "", false
	}
	fingerprint, ok := value.(string)
	return fingerprint, ok && fingerprint != ""
}

type closeObservedConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *closeObservedConn) Close() error {
	if c.onClose != nil {
		c.once.Do(c.onClose)
	}
	return c.Conn.Close()
}

// DialTLSContext returns a net/http TLS dial callback that performs WebPKI
// verification and registers the peer leaf against the returned *tls.Conn.
func (r *Registry) DialTLSContext(
	dialContext func(context.Context, string, string) (net.Conn, error),
	config *tls.Config,
	handshakeTimeout time.Duration,
) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		rawConn, err := dialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if config != nil {
			cfg = config.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		var tlsConn *tls.Conn
		observed := &closeObservedConn{Conn: rawConn}
		observed.onClose = func() { r.Delete(tlsConn) }
		tlsConn = tls.Client(observed, cfg)
		handshakeCtx := ctx
		cancel := func() {}
		if handshakeTimeout > 0 {
			handshakeCtx, cancel = context.WithTimeout(ctx, handshakeTimeout)
		}
		err = tlsConn.HandshakeContext(handshakeCtx)
		cancel()
		if err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			r.Record(tlsConn, state.PeerCertificates[0].Raw)
		}
		return tlsConn, nil
	}
}

// Transport adds per-request GotConn attribution to a pooled transport.
type Transport struct {
	Base     http.RoundTripper
	Registry *Registry
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	a, tracked := begin(req.Context())
	if !tracked {
		return t.Base.RoundTrip(req)
	}

	var state struct {
		sync.Mutex
		gotConn     bool
		fingerprint string
		found       bool
	}
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		fingerprint, found := t.Registry.Lookup(info.Conn)
		state.Lock()
		state.gotConn = true
		state.fingerprint = fingerprint
		state.found = found
		state.Unlock()
	}}
	requestWithTrace := req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	response, err := t.Base.RoundTrip(requestWithTrace)
	state.Lock()
	gotConn := state.gotConn
	fingerprint := state.fingerprint
	found := state.found
	state.Unlock()

	certain := err == nil && response != nil && gotConn && found
	if !a.finish(fingerprint, certain) {
		reason := "overlapping request attribution"
		switch {
		case err != nil:
			reason = "round trip failed"
		case response == nil:
			reason = "round trip returned no response"
		case !gotConn:
			reason = "GotConn was not called"
		case !found:
			reason = "serving connection was not in TLS registry"
		}
		log.Printf("llm.upstream_cert_sha256_omitted reason=%q", reason)
	}
	return response, err
}

// CloseIdleConnections preserves http.Client's pool cleanup behavior.
func (t *Transport) CloseIdleConnections() {
	if closer, ok := t.Base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
