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

func (c *responseStatsConn) SelectedLeafDER() []byte {
	return enclavetls.SelectedLeafDER(c.Conn)
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

// readRequest reads a minimal HTTP/1.1 request: status line + headers + body.
// Returns method + path + bearer + idempotency key + body. We don't validate Host or any
// other field; the dispatch happens by path in serveOne.
func readRequest(r net.Conn) (method, path, bearer, idempotencyKey string, body []byte, err error) {
	br := bufio.NewReader(r)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return "", "", "", "", nil, err
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
			return "", "", "", "", nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
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
		case "content-length":
			parsed, parseErr := strconv.Atoi(v)
			if parseErr != nil || parsed < 0 {
				return "", "", "", "", nil, fmt.Errorf("invalid content-length")
			}
			if parsed > maxRequestBodyBytes {
				return "", "", "", "", nil, errBodyTooLarge
			}
			contentLength = parsed
		}
	}
	body = make([]byte, contentLength)
	if contentLength > 0 {
		if _, err := io.ReadFull(br, body); err != nil {
			return "", "", "", "", nil, err
		}
	}
	return method, path, bearer, idempotencyKey, body, nil
}

func parseRequestTarget(rawPath string) (string, []byte, error) {
	u, err := url.ParseRequestURI(rawPath)
	if err != nil {
		return rawPath, nil, nil
	}
	nonceHex := u.Query().Get("nonce")
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
// binding the exact TLS leaf cert selected for this connection. Clients fetch
// this before sending prompts; verify the attestation chain + measurement, then
// check the cert presented in their TLS handshake is the cert bound in the
// document/JWT.
//
// nonce: ?nonce=<hex> in the query string. Optional but recommended —
// a client-supplied freshness token so the doc is provably not a replay.
func serveAttestation(conn io.Writer, leafDER, deviceBlob, nonce []byte) {
	if leafDER == nil {
		writeError(conn, 503, "TLS not enabled in this enclave; attestation requires a bound cert")
		return
	}
	doc, err := attestation.Get(leafDER, deviceBlob, nonce)
	if err != nil {
		writeError(conn, 500, "attestation: "+err.Error())
		return
	}
	fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
		len(doc))
	conn.Write(doc)
}

func writeError(w io.Writer, status int, message string) {
	writeErrorWithSource(w, status, message, "router")
}

func writeProviderError(w io.Writer, status int, message string) {
	writeErrorWithSource(w, status, message, "provider")
}

func writeErrorWithSource(w io.Writer, status int, message, source string) {
	if source == "" {
		source = "router"
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{"status": status, "message": message, "source": source},
	})
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, statusText(status), len(body))
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
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, statusText(status), len(body))
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
