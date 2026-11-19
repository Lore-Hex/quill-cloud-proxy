package llm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const fortanixAuthority = "ctf.armet.ai"
const fortanixNativeModel = "GLM-5.3-Flash"

// This candidate transport is not selected by the live ZDR client. Give it
// one request and a platform-specific authenticated TLS dialer. The HTTP
// transport cannot write inference headers or body until DialTLSContext returns.
func fortanixAttestedClient(key string, dial func(context.Context, string, string) (*tls.Conn, error), appraise func(context.Context, []byte, [32]byte, [32]byte) error) *http.Client {
	var used atomic.Bool
	base := fortanixRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.EscapedPath() != "/v1/chat/completions" || req.URL.RawQuery != "" || req.URL.ForceQuery || key == "" || dial == nil || appraise == nil || !used.CompareAndSwap(false, true) {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, errors.New("Fortanix: invalid or reused attested request")
		}
		req = req.Clone(req.Context())
		if err := fortanixPinWireModel(req); err != nil {
			return nil, err
		}
		var attempted atomic.Bool
		tr := &http.Transport{DisableKeepAlives: true, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 64 << 10, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
		tr.DialTLSContext = func(_ context.Context, netw, address string) (net.Conn, error) {
			if address != fortanixAuthority+":443" || !attempted.CompareAndSwap(false, true) {
				return nil, errors.New("Fortanix: invalid or repeated dial")
			}
			proofCtx, cancel := context.WithTimeout(req.Context(), 90*time.Second)
			defer cancel()
			conn, err := dial(proofCtx, netw, address)
			if err != nil {
				return nil, err
			}
			if err := fortanixCheckConn(proofCtx, conn, key, appraise); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		}
		return tr.RoundTrip(req)
	})
	return &http.Client{Timeout: defaultStreamingHTTPTimeout, Transport: &pinnedProviderEgressTransport{base: base, host: fortanixAuthority}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Fortanix redirects forbidden") }}
}

// Validate the actual serialized model before dialing. Only these checked bytes
// can be sent. Do not forward a second body or accept ambiguous model keys.
func fortanixPinWireModel(req *http.Request) error {
	const maxWire = 8 << 20
	refused := errors.New("Fortanix: invalid request or unqualified model")
	if req.Body == nil {
		return refused
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, maxWire+1))
	_ = req.Body.Close()
	if err != nil || len(raw) > maxWire {
		return refused
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return refused
	}
	found := false
	for d.More() {
		k, err := d.Token()
		key, ok := k.(string)
		if err != nil || !ok {
			return refused
		}
		if strings.EqualFold(key, "model") {
			var model string
			if key != "model" || found || d.Decode(&model) != nil || model != fortanixNativeModel {
				return refused
			}
			found = true
		} else {
			var skip json.RawMessage
			if d.Decode(&skip) != nil {
				return refused
			}
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || !found {
		return refused
	}
	if _, err = d.Token(); err != io.EOF {
		return refused
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	req.ContentLength = int64(len(raw))
	req.GetBody = nil
	return nil
}

type fortanixRoundTrip func(*http.Request) (*http.Response, error)

func (f fortanixRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fortanixCheckConn(ctx context.Context, conn *tls.Conn, key string, appraise func(context.Context, []byte, [32]byte, [32]byte) error) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("Fortanix: missing challenge deadline")
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.HandshakeContext(ctx); err != nil {
		return err
	}
	state := conn.ConnectionState()
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || state.PeerCertificates[0].VerifyHostname(fortanixAuthority) != nil ||
		(state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1") {
		return errors.New("Fortanix: unauthenticated or incompatible channel")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	spki := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	query := url.Values{"nonce": {hex.EncodeToString(nonce[:])}, "model": {fortanixNativeModel}, "version": {"2"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+fortanixAuthority+"/v1/attestation/report?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	if err := req.Write(conn); err != nil {
		return err
	}
	const maxBytes = 1 << 20
	// Bound total wire bytes as well as the decoded body. Never hand a socket
	// with leftover buffered data, a protocol upgrade, or a close signal to HTTP.
	br := bufio.NewReader(io.LimitReader(conn, maxBytes+(64<<10)+1))
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return errors.New("Fortanix: unreadable report response")
	}
	if resp.StatusCode != http.StatusOK || resp.Close || resp.ProtoMajor != 1 || resp.ProtoMinor != 1 || resp.ContentLength > maxBytes {
		return errors.New("Fortanix: report request refused or channel not reusable")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil || len(data) > maxBytes || br.Buffered() != 0 {
		return errors.New("Fortanix: incomplete or oversized report")
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if err := appraise(ctx, data, nonce, spki); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return conn.SetDeadline(time.Time{})
}
