package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
)

var getAttestation = attestation.Get

type responseStatsConn struct {
	net.Conn
	mu            sync.Mutex
	status        int
	responseBytes int
}

func (c *responseStatsConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status == 0 {
		c.status = parseHTTPStatus(p)
	}
	c.responseBytes += n
	return n, err
}

func (c *responseStatsConn) Snapshot() (status int, responseBytes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status, c.responseBytes
}

func (c *responseStatsConn) ResetSnapshot() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = 0
	c.responseBytes = 0
}

func (c *responseStatsConn) SelectedLeafDER() []byte {
	return enclavetls.SelectedLeafDER(c.Conn)
}

func (c *responseStatsConn) SelectedExporter() ([]byte, error) {
	return enclavetls.SelectedExporter(c.Conn)
}

func parseHTTPStatus(p []byte) int {
	if !bytes.HasPrefix(p, []byte("HTTP/")) {
		return 0
	}
	line := p
	if i := bytes.IndexByte(p, '\n'); i >= 0 {
		line = p[:i]
	}
	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		return 0
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return status
}

func outcomeForStatus(status int) string {
	switch {
	case status >= 200 && status < 400:
		return "ok"
	case status >= 400 && status < 500:
		return "client_error"
	case status >= 500:
		return "server_error"
	default:
		return "no_response"
	}
}

// allowlistKeyInfoStatus maps the control-plane /internal/gateway/key status to
// a client-safe status for the /v1/key relay AND reports whether the
// control-plane body is safe to relay. `relay` is true ONLY for an expected
// status; anything unexpected (a 1xx/3xx, or ANY 5xx — including a raw 502 that
// would otherwise equal the collapsed value) returns (502, false) so the caller
// drops the possibly-internal body (codex). Never infer "expected" by comparing
// the mapped status to the original — 502 maps to 502.
func allowlistKeyInfoStatus(status int) (safe int, relay bool) {
	switch status {
	case 200, 400, 401, 403, 404, 429, 503:
		return status, true
	default:
		return 502, false
	}
}

type streamStatsWriter struct {
	w         io.Writer
	bytes     int
	firstByte time.Time
}

func newStreamStatsWriter(w io.Writer) *streamStatsWriter {
	return &streamStatsWriter{w: w}
}

func (w *streamStatsWriter) Write(p []byte) (int, error) {
	if len(p) > 0 && w.firstByte.IsZero() {
		w.firstByte = time.Now()
	}
	n, err := w.w.Write(p)
	w.bytes += n
	return n, err
}

func (w *streamStatsWriter) BytesWritten() int {
	return w.bytes
}

func (w *streamStatsWriter) FirstWriteSeconds(start time.Time) float64 {
	if w.firstByte.IsZero() {
		return 0
	}
	return maxDurationSeconds(w.firstByte.Sub(start), 0.001)
}

func maxDurationSeconds(duration time.Duration, floor float64) float64 {
	seconds := duration.Seconds()
	if seconds < floor {
		return floor
	}
	return seconds
}

type requestAttributionHeaders struct {
	SessionID          string
	HTTPReferer        string
	App                string
	AppCategories      []string
	OpenRouterMetadata bool
}

// readRequest reads a minimal HTTP/1.1 request: status line + headers + body.
// Attribution headers are retained inside the enclave and sent only to the
// TrustedRouter control plane, never to model providers.
func readRequest(br *bufio.Reader) (method, path, bearer, idempotencyKey string, attribution requestAttributionHeaders, body []byte, err error) {
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return "", "", "", "", attribution, nil, err
	}
	parts := strings.Fields(statusLine)
	if len(parts) >= 2 {
		method = parts[0]
		path = parts[1]
	}

	contentLength := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", "", "", "", attribution, nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "authorization":
			if strings.HasPrefix(v, "Bearer ") {
				bearer = v[len("Bearer "):]
			}
		case "x-api-key":
			if bearer == "" {
				bearer = strings.TrimSpace(v)
			}
		case "idempotency-key":
			idempotencyKey = strings.TrimSpace(v)
		case "x-session-id":
			attribution.SessionID = v
		case "http-referer":
			attribution.HTTPReferer = v
		case "x-openrouter-title":
			attribution.App = v
		case "x-title":
			if attribution.App == "" {
				attribution.App = v
			}
		case "x-openrouter-categories":
			attribution.AppCategories = splitAttributionCategories(v)
		case "x-openrouter-metadata", "x-openrouter-experimental-metadata":
			attribution.OpenRouterMetadata = strings.EqualFold(v, "enabled")
		case "content-length":
			parsed, parseErr := strconv.Atoi(v)
			if parseErr != nil || parsed < 0 {
				return "", "", "", "", attribution, nil, fmt.Errorf("invalid content-length")
			}
			if parsed > maxRequestBodyBytes {
				return "", "", "", "", attribution, nil, errBodyTooLarge
			}
			contentLength = parsed
		}
	}
	body = make([]byte, contentLength)
	if contentLength > 0 {
		if _, err := io.ReadFull(br, body); err != nil {
			return "", "", "", "", attribution, nil, err
		}
	}
	return method, path, bearer, idempotencyKey, attribution, body, nil
}

func splitAttributionCategories(value string) []string {
	var categories []string
	for _, item := range strings.Split(value, ",") {
		if category := strings.TrimSpace(item); category != "" {
			categories = append(categories, category)
		}
	}
	return categories
}

func parseRequestTarget(rawPath string) (string, []byte, error) {
	u, err := url.ParseRequestURI(rawPath)
	if err != nil {
		return rawPath, nil, nil
	}
	query := u.Query()
	nonceValues := query["nonce"]
	// G6 single-slot closure: the verifier requires both its fresh nonce and
	// the RFC 9266 exporter, so the caller-controlled channel must remain one
	// nonce slot. Reject duplicates instead of letting Query.Get silently pick
	// one and weakening that premise later.
	if len(nonceValues) > 1 {
		return "", nil, fmt.Errorf("multiple nonce parameters")
	}
	nonceHex := ""
	if len(nonceValues) == 1 {
		nonceHex = nonceValues[0]
	}
	if nonceHex == "" {
		return u.Path, nil, nil
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", nil, fmt.Errorf("invalid attestation nonce")
	}
	if len(nonce) > maxAttestationNonceBytes {
		return "", nil, fmt.Errorf("attestation nonce too large")
	}
	return u.Path, nonce, nil
}

func isUnsupportedResponsesEndpoint(method, routePath string) bool {
	if !strings.HasPrefix(routePath, "/v1/responses/") {
		return false
	}
	if method == "GET" && strings.HasSuffix(routePath, "/input_items") {
		return true
	}
	if method == "POST" && strings.HasSuffix(routePath, "/cancel") {
		return true
	}
	if method == "POST" && routePath == "/v1/responses/compact" {
		return true
	}
	if method == "GET" && strings.Count(strings.TrimPrefix(routePath, "/v1/responses/"), "/") == 0 {
		return true
	}
	if method == "DELETE" && strings.Count(strings.TrimPrefix(routePath, "/v1/responses/"), "/") == 0 {
		return true
	}
	return false
}

// serveAttestation answers GET /attestation with a hardware-signed document
// binding the exact TLS leaf cert and RFC 9266 exporter selected for this
// connection. Clients fetch this before sending prompts; verify the attestation
// chain + measurement, then check the cert and same-session exporter presented
// in their TLS handshake are bound in the document/JWT.
//
// nonce: ?nonce=<hex> in the query string. Optional but recommended —
// a client-supplied freshness token so the doc is provably not a replay.
func serveAttestation(conn io.Writer, leafDER, deviceBlob, nonce, channelBinding []byte) bool {
	if leafDER == nil {
		writeError(conn, 503, "TLS not enabled in this enclave; attestation requires a bound cert")
		return false
	}
	doc, err := getAttestation(leafDER, deviceBlob, nonce, channelBinding)
	if err != nil {
		writeError(conn, 500, "attestation: "+err.Error())
		return false
	}
	fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n",
		len(doc))
	conn.Write(doc)
	return true
}

func writeError(w io.Writer, status int, message string) {
	writeErrorWithSource(w, status, message, "router")
}

func writeProviderError(w io.Writer, status int, message string) {
	writeErrorWithSource(w, status, message, "provider")
}

func writeErrorWithSource(w io.Writer, status int, message, source string) {
	writeErrorWithSourceHeaders(w, status, message, source, nil)
}

// writeErrorWithSourceHeaders is writeErrorWithSource plus extra response
// headers (e.g. Retry-After relayed from a control-plane 429 so agents can
// back off until the key's spend window resets).
func writeErrorWithSourceHeaders(w io.Writer, status int, message, source string, extra map[string]string) {
	if source == "" {
		source = "router"
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{"status": status, "message": message, "source": source},
	})
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n",
		status, statusText(status), len(body))
	for name, value := range extra {
		if value != "" {
			fmt.Fprintf(w, "%s: %s\r\n", name, value)
		}
	}
	io.WriteString(w, "\r\n")
	w.Write(body)
}

func writeAdapterOpenAIError(w io.Writer, err *adapter.AdapterError) {
	errType := "invalid_request_error"
	code := "bad_request"
	if err.Status == 501 {
		errType = "not_supported_in_alpha"
		code = "not_supported_in_alpha"
	}
	writeOpenAIError(w, err.Status, err.Message, errType, code, err.Context)
}

func writeOpenAIError(w io.Writer, status int, message, errType, code, param string) {
	if errType == "" {
		errType = "invalid_request_error"
	}
	if code == "" {
		code = errType
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    errType,
			"param":   orNilString(param),
			"code":    code,
			"source":  "router",
		},
	})
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, statusText(status), len(body))
	w.Write(body)
}

func orNilString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func writeJSONResponse(w io.Writer, status int, body []byte) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, statusText(status), len(body))
	w.Write(body)
}

func writeResponseHead(w io.Writer, status int, contentType string) error {
	if contentType == "" {
		contentType = "text/event-stream"
	}
	_, err := fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\nTransfer-Encoding: chunked\r\nContent-Type: %s\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nConnection: close\r\n\r\n",
		status, statusText(status), contentType)
	return err
}

func statusText(status int) string {
	switch status {
	case 200:
		return "OK"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 413:
		return "Payload Too Large"
	case 404:
		return "Not Found"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 500:
		return "Internal Server Error"
	default:
		return "Error"
	}
}

// chunkedWriter wraps a net.Conn writer with HTTP/1.1 chunked transfer-encoding.
type chunkedWriter struct {
	w io.Writer
}

func newChunkedWriter(w io.Writer) *chunkedWriter { return &chunkedWriter{w: w} }

func (c *chunkedWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := fmt.Fprintf(c.w, "%x\r\n", len(p)); err != nil {
		return 0, err
	}
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	if _, err := c.w.Write([]byte("\r\n")); err != nil {
		return n, err
	}
	return n, nil
}

func (c *chunkedWriter) Close() error {
	_, err := c.w.Write([]byte("0\r\n\r\n"))
	return err
}

// newRequestID returns "chatcmpl-<32 hex>" with no allocations beyond the buffer.
func newRequestID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return "chatcmpl-" + hex.EncodeToString(buf[:])
}

func newMessageID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return "msg_" + hex.EncodeToString(buf[:])
}

// upstreamErrorResponse maps a provider/upstream error to the status + message
// to return to the client. Provider clients wrap upstream HTTP failures as
// "...http <status>: <body>" (see internal/llm/*.go); when we recognize that
// shape we surface the upstream status and (truncated) body so callers get the
// real reason — e.g. an Anthropic 400 validation error — instead of an opaque
// "provider error". Anything we can't classify stays a generic 502. Upstream
// 4xx/5xx bodies are API status/validation messages (no keys, no user data).
func upstreamErrorResponse(err error) (int, string) {
	if err == nil {
		return 502, "provider error"
	}
	var aerr *adapter.AdapterError
	if asAdapterErr(err, &aerr) {
		return aerr.Status, aerr.Message
	}
	s := err.Error()
	if i := strings.LastIndex(s, "http "); i >= 0 {
		rest := s[i+len("http "):]
		if c := strings.IndexByte(rest, ':'); c > 0 {
			if code, e := strconv.Atoi(strings.TrimSpace(rest[:c])); e == nil && code >= 400 && code < 600 {
				body := strings.TrimSpace(rest[c+1:])
				if len(body) > 1200 {
					body = body[:1200]
				}
				if body != "" {
					return code, body
				}
			}
		}
	}
	return 502, "provider error"
}

// writeAnthropicError writes the Anthropic-shaped error envelope the
// Messages API uses: {"type":"error","error":{"type":...,"message":...}}.
func writeAnthropicError(w io.Writer, status int, message string) {
	writeAnthropicErrorWithSource(w, status, message, "router")
}

func writeAnthropicProviderError(w io.Writer, status int, message string) {
	writeAnthropicErrorWithSource(w, status, message, "provider")
}

func writeAnthropicErrorWithSource(w io.Writer, status int, message, source string) {
	writeAnthropicErrorWithSourceHeaders(w, status, message, source, nil)
}

func writeAnthropicErrorWithSourceHeaders(
	w io.Writer, status int, message, source string, extra map[string]string,
) {
	if source == "" {
		source = "router"
	}
	body, _ := json.Marshal(map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    anthropicErrorType(status),
			"message": message,
			"source":  source,
		},
	})
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n",
		status, statusText(status), len(body))
	for name, value := range extra {
		if value != "" {
			fmt.Fprintf(w, "%s: %s\r\n", name, value)
		}
	}
	io.WriteString(w, "\r\n")
	w.Write(body)
}

// writeAnthropicStreamError emits the Messages-API streaming error event.
func writeAnthropicStreamError(w io.Writer, message string) error {
	body, err := json.Marshal(map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    "api_error",
			"message": message,
			"source":  "provider",
		},
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: error\ndata: %s\n\n", body)
	return err
}

func anthropicErrorType(status int) string {
	switch status {
	case 400, 413:
		return "invalid_request_error"
	case 401:
		return "authentication_error"
	case 403:
		return "permission_error"
	case 404:
		return "not_found_error"
	case 429:
		return "rate_limit_error"
	case 529, 503:
		return "overloaded_error"
	default:
		return "api_error"
	}
}

func newResponseID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return "resp_" + hex.EncodeToString(buf[:])
}

func newRequestLogID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return "rlog_" + hex.EncodeToString(buf[:])
}
