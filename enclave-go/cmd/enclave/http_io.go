package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
)

var getAttestation = attestation.Get

const (
	maxHTTPHeaderLineBytes = 16*1024 - 1
	maxHTTPHeaderBytes     = 64 << 10
	maxHTTPHeaderCount     = 100
	// A bufio.Reader may read beyond the current request body. Preserve legal
	// pipelining, but bound how much already-read data can cross a response
	// boundary before the next request is parsed.
	maxHTTPBufferedCarryoverBytes = 8 << 10
)

var errHeadersTooLarge = errors.New("request headers too large")
var errInvalidInferenceReceipt = errors.New("invalid x-inference-receipt header")
var errAmbiguousRequestFraming = errors.New("ambiguous request framing")
var errUnsupportedRequestTransferEncoding = errors.New("request transfer-encoding is not supported")
var errMalformedRequestHeaders = errors.New("malformed request headers")
var errMalformedRequestLine = errors.New("malformed request line")

var inferenceReceiptNoncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,88}$`)

var (
	upstreamAPIKeyPattern = regexp.MustCompile(`(?i)\b(sk|rk)-[A-Za-z0-9_\-*]{4,}`)
	upstreamBearerPattern = regexp.MustCompile(`(?i)bearer\s+\S+`)
)

type responseStatsConn struct {
	net.Conn
	writeMu       sync.Mutex
	mu            sync.Mutex
	status        int
	responseBytes int
	requestID     string
	keepAlive     bool
	reusable      bool
}

func (c *responseStatsConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if responseWriteTimeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(responseWriteTimeout))
		defer func() {
			_ = c.Conn.SetWriteDeadline(time.Time{})
		}()
	}
	wireBytes := p
	injectedHeaderBytes := 0
	c.mu.Lock()
	if c.status == 0 {
		requestID := c.requestID
		// The injection opportunity exists only on the first write. Clearing the
		// ID here keeps a partial or non-HTTP first write from being modified later.
		c.requestID = ""
		if statusLineEnd := bytes.Index(p, []byte("\r\n")); requestID != "" && bytes.HasPrefix(p, []byte("HTTP/")) && statusLineEnd >= 0 {
			statusLineEnd += len("\r\n")
			headers := []byte("x-request-id: " + requestID + "\r\nrequest-id: " + requestID + "\r\n")
			wireBytes = make([]byte, 0, len(p)+len(headers))
			wireBytes = append(wireBytes, p[:statusLineEnd]...)
			wireBytes = append(wireBytes, headers...)
			wireBytes = append(wireBytes, p[statusLineEnd:]...)
			injectedHeaderBytes = len(headers)
		}
	}
	c.mu.Unlock()

	n, err := c.Conn.Write(wireBytes)
	if err == nil && n != len(wireBytes) {
		err = io.ErrShortWrite
	}
	c.mu.Lock()
	if c.status == 0 {
		c.status = parseHTTPStatus(p)
	}
	c.responseBytes += n
	if err != nil {
		c.keepAlive = false
		c.reusable = false
	}
	c.mu.Unlock()
	if injectedHeaderBytes == 0 {
		return n, err
	}
	if err == nil {
		return len(p), nil
	}
	statusLineBytes := bytes.Index(p, []byte("\r\n")) + len("\r\n")
	callerBytes := n
	if n > statusLineBytes {
		callerBytes = statusLineBytes
		if n > statusLineBytes+injectedHeaderBytes {
			callerBytes += n - statusLineBytes - injectedHeaderBytes
		}
	}
	if callerBytes > len(p) {
		callerBytes = len(p)
	}
	return callerBytes, err
}

func (c *responseStatsConn) Snapshot() (status int, responseBytes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status, c.responseBytes
}

// ResetSnapshot clears response statistics and any pending request ID.
func (c *responseStatsConn) ResetSnapshot() {
	c.BeginRequest("")
}

func (c *responseStatsConn) BeginRequest(requestID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = 0
	c.responseBytes = 0
	c.requestID = requestID
	c.keepAlive = false
	c.reusable = false
}

func (c *responseStatsConn) SetResponseKeepAlive(keepAlive bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keepAlive = keepAlive
	c.reusable = keepAlive
}

func (c *responseStatsConn) ResponseKeepAlive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keepAlive
}

func (c *responseStatsConn) DisableResponseReuse() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keepAlive = false
	c.reusable = false
}

func (c *responseStatsConn) ResponseReusable() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reusable
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
	ClientContext      clientContextHeaders
	InferenceReceipt   string
	httpVersion        string
	connectionClose    bool
}

// readRequest reads a minimal HTTP/1.1 request: status line + headers + body.
// Attribution headers are retained inside the enclave and sent only to the
// TrustedRouter control plane, never to model providers.
func readRequest(br *bufio.Reader) (method, path, bearer, idempotencyKey string, attribution requestAttributionHeaders, body []byte, err error) {
	return readRequestWithHeadersRead(br, nil)
}

func readRequestWithHeadersRead(
	br *bufio.Reader,
	headersRead func(),
) (method, path, bearer, idempotencyKey string, attribution requestAttributionHeaders, body []byte, err error) {
	statusLineBytes, err := readBoundedHTTPLine(br)
	if err != nil {
		return "", "", "", "", attribution, nil, err
	}
	headerBytes := len(statusLineBytes)
	statusLine := strings.TrimSuffix(string(statusLineBytes), "\r\n")
	parts := strings.Split(statusLine, " ")
	if len(parts) != 3 || !validHTTPHeaderFieldName(parts[0]) || !validHTTPRequestTarget(parts[1]) ||
		(parts[2] != "HTTP/1.1" && parts[2] != "HTTP/1.0") {
		return "", "", "", "", attribution, nil, errMalformedRequestLine
	}
	method = parts[0]
	path = parts[1]
	attribution.httpVersion = parts[2]

	contentLength := 0
	contentLengthSeen := false
	transferEncodingSeen := false
	headerCount := 0
	for {
		lineBytes, err := readBoundedHTTPLine(br)
		if err != nil {
			return "", "", "", "", attribution, nil, err
		}
		headerBytes += len(lineBytes)
		if headerBytes > maxHTTPHeaderBytes {
			return "", "", "", "", attribution, nil, errHeadersTooLarge
		}
		line := strings.TrimSuffix(string(lineBytes), "\r\n")
		if line == "" {
			break
		}
		headerCount++
		if headerCount > maxHTTPHeaderCount {
			return "", "", "", "", attribution, nil, errHeadersTooLarge
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || !validHTTPHeaderFieldName(k) {
			return "", "", "", "", attribution, nil, errMalformedRequestHeaders
		}
		if !validHTTPHeaderFieldValue(v) {
			return "", "", "", "", attribution, nil, errMalformedRequestHeaders
		}
		v = strings.Trim(v, " \t")
		switch strings.ToLower(k) {
		case "connection":
			for _, token := range strings.Split(v, ",") {
				if strings.EqualFold(strings.TrimSpace(token), "close") {
					attribution.connectionClose = true
				}
			}
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
		case "x-inference-receipt":
			// Disabled receipt support is intentionally indistinguishable from
			// the pre-receipt server, including for malformed opt-in values.
			if inferenceReceiptsEnabled() {
				if !inferenceReceiptNoncePattern.MatchString(v) {
					return "", "", "", "", attribution, nil, errInvalidInferenceReceipt
				}
				attribution.InferenceReceipt = v
			}
		case "user-agent":
			captureBoundedClientHeader(
				&attribution.ClientContext.userAgent,
				&attribution.ClientContext.userAgentSet,
				v,
				maxClientUserAgentBytes,
				&attribution.ClientContext.userAgentTooLong,
			)
		case "x-stainless-lang":
			captureBoundedStainlessHeader(&attribution.ClientContext.stainlessLang, &attribution.ClientContext.stainlessLangSet, v, &attribution.ClientContext)
		case "x-stainless-runtime":
			captureBoundedStainlessHeader(&attribution.ClientContext.stainlessRuntime, &attribution.ClientContext.stainlessRuntimeSet, v, &attribution.ClientContext)
		case "x-stainless-runtime-version":
			captureBoundedStainlessHeader(&attribution.ClientContext.stainlessRuntimeVersion, &attribution.ClientContext.stainlessRuntimeVersionSet, v, &attribution.ClientContext)
		case "x-stainless-os":
			captureBoundedStainlessHeader(&attribution.ClientContext.stainlessOS, &attribution.ClientContext.stainlessOSSet, v, &attribution.ClientContext)
		case "x-stainless-arch":
			captureBoundedStainlessHeader(&attribution.ClientContext.stainlessArch, &attribution.ClientContext.stainlessArchSet, v, &attribution.ClientContext)
		case "x-stainless-retry-count":
			captureBoundedStainlessHeader(&attribution.ClientContext.stainlessRetryCount, &attribution.ClientContext.stainlessRetryCountSet, v, &attribution.ClientContext)
		case "x-stainless-timeout":
			captureBoundedStainlessHeader(&attribution.ClientContext.stainlessTimeout, &attribution.ClientContext.stainlessTimeoutSet, v, &attribution.ClientContext)
		case "x-stainless-read-timeout":
			captureBoundedStainlessHeader(&attribution.ClientContext.stainlessReadTimeout, &attribution.ClientContext.stainlessReadTimeoutSet, v, &attribution.ClientContext)
		case "x-tr-client":
			captureBoundedClientHeader(
				&attribution.ClientContext.trClient,
				&attribution.ClientContext.trClientSet,
				v,
				maxTRClientHeaderBytes,
				&attribution.ClientContext.trClientTooLong,
			)
		case "content-length":
			// Multiple Content-Length fields are refused even when their values
			// agree. Accepting duplicates creates parser-differential ambiguity
			// across intermediaries and is unnecessary on this raw HTTP path.
			if contentLengthSeen {
				return "", "", "", "", attribution, nil, errAmbiguousRequestFraming
			}
			contentLengthSeen = true
			parsed, parseErr := parseHTTPContentLength(v)
			if parseErr != nil || parsed < 0 {
				return "", "", "", "", attribution, nil, fmt.Errorf("invalid content-length")
			}
			if parsed > maxRequestBodyBytes {
				return "", "", "", "", attribution, nil, errBodyTooLarge
			}
			contentLength = parsed
		case "transfer-encoding":
			transferEncodingSeen = true
		}
	}
	// Never choose between Content-Length and Transfer-Encoding. Different
	// parsers make different choices, which is the classic request-smuggling
	// primitive; reject the connection before reading or reusing any body.
	if contentLengthSeen && transferEncodingSeen {
		return "", "", "", "", attribution, nil, errAmbiguousRequestFraming
	}
	// This hand-rolled reader supports only fixed-length request bodies. In
	// particular, chunked request bodies are refused instead of guessed at or
	// accidentally reinterpreted as the next request on a reused connection.
	if transferEncodingSeen {
		return "", "", "", "", attribution, nil, errUnsupportedRequestTransferEncoding
	}
	if headersRead != nil {
		headersRead()
	}
	if contentLength > 0 {
		// Authentication happens after the request has been parsed. Keep the
		// stdlib's MaxBytesReader at this unauthenticated boundary as a second
		// guard behind the Content-Length precheck, including if body framing is
		// extended later.
		requestBody := http.MaxBytesReader(
			nil,
			io.NopCloser(io.LimitReader(br, int64(contentLength))),
			int64(maxRequestBodyBytes),
		)
		defer requestBody.Close()
		body, err = io.ReadAll(requestBody)
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return "", "", "", "", attribution, nil, errBodyTooLarge
		}
		if err != nil {
			return "", "", "", "", attribution, nil, err
		}
		if len(body) != contentLength {
			return "", "", "", "", attribution, nil, io.ErrUnexpectedEOF
		}
	}
	return method, path, bearer, idempotencyKey, attribution, body, nil
}

func validHTTPHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func validHTTPHeaderFieldValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < ' ' && value[i] != '\t' || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func validHTTPRequestTarget(target string) bool {
	if target == "" {
		return false
	}
	for i := 0; i < len(target); i++ {
		if target[i] < '!' || target[i] > '~' {
			return false
		}
	}
	return true
}

func parseHTTPContentLength(value string) (int, error) {
	if value == "" {
		return 0, errAmbiguousRequestFraming
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, errAmbiguousRequestFraming
		}
	}
	return strconv.Atoi(value)
}

func captureBoundedStainlessHeader(destination *string, set *bool, value string, raw *clientContextHeaders) {
	tooLong := 0
	captureBoundedClientHeader(destination, set, value, maxClientStainlessValueBytes, &tooLong)
	raw.stainlessValuesTooLong += tooLong
}

func captureBoundedClientHeader(destination *string, set *bool, value string, maximum int, tooLong *int) {
	if len(value) > maximum {
		(*tooLong)++
		return
	}
	*destination = value
	*set = true
}

func readBoundedHTTPLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxHTTPHeaderLineBytes {
		return nil, errHeadersTooLarge
	}
	if err != nil {
		return nil, err
	}
	// Bare LF is not accepted. Allowing multiple line-ending grammars is a
	// parser differential that can turn one intermediary request into two.
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return nil, errMalformedRequestHeaders
	}
	return line, nil
}

func splitAttributionCategories(value string) []string {
	// Retain one entry beyond the supported maximum so validation can report
	// the error without strings.Split allocating proportional to attacker input.
	categories := make([]string, 0, 3)
	for len(categories) < 3 {
		item, rest, found := strings.Cut(value, ",")
		if category := strings.TrimSpace(item); category != "" {
			categories = append(categories, category)
		}
		if !found {
			break
		}
		value = rest
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
		disableResponseReuse(conn)
		writeError(conn, 503, "TLS not enabled in this enclave; attestation requires a bound cert")
		return false
	}
	doc, err := getAttestation(leafDER, deviceBlob, nonce, channelBinding, nil)
	if err != nil {
		disableResponseReuse(conn)
		writeError(conn, 500, "attestation: "+err.Error())
		return false
	}
	fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: %s\r\n\r\n",
		len(doc), responseConnection(conn))
	conn.Write(doc)
	return true
}

func writeHealthResponse(w io.Writer, keepAlive bool, processingStartedAt time.Time) {
	body := []byte(`{"status":"ok"}`)
	connection := "close"
	if keepAlive {
		connection = "keep-alive"
	}
	processingMilliseconds := float64(time.Since(processingStartedAt).Nanoseconds()) / 1_000_000
	fmt.Fprintf(
		w,
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nServer-Timing: gateway;dur=%.3f\r\nConnection: %s\r\n\r\n",
		len(body),
		processingMilliseconds,
		connection,
	)
	_, _ = w.Write(body)
}

func writeError(w io.Writer, status int, message string) {
	writeErrorWithSource(w, status, message, "router")
}

func writeProviderError(w io.Writer, status int, message string) {
	writeErrorWithSource(w, status, message, "provider")
}

// shouldRetryHeader tells an SDK whether re-sending is safe, overriding its own
// status heuristics. OpenAI's clients honour exactly this header; ours do too.
//
// It exists because the status code alone cannot answer the only question that
// matters to a retrying client: did a provider already run? A 502 from "could
// not reach the provider" and a 502 from "the generation succeeded and then
// settlement failed" are indistinguishable from the outside, and they call for
// opposite behaviour.
const shouldRetryHeader = "x-should-retry"

// writeSpentError reports a failure that happened AFTER a provider produced —
// and we paid for — a result. Re-sending regenerates it.
//
// The caller is not double-charged: authorization is idempotent per
// Idempotency-Key and settlement is exactly-once per authorization. What is
// lost is real money to the upstream provider, and the caller may receive a
// different answer than the one already generated.
//
// These are usually 500 or 502, and 502 is precisely the status an SDK treats
// as safe to move domains on, so this header is the only thing standing between
// a settlement blip and a second generation.
func writeSpentError(w io.Writer, status int, message string) {
	writeSpentErrorWithSource(w, status, message, "router")
}

// writeSpentProviderError is writeSpentError for failures attributed to the
// upstream provider rather than to us.
func writeSpentProviderError(w io.Writer, status int, message string) {
	writeSpentErrorWithSource(w, status, message, "provider")
}

func writeSpentErrorWithSource(w io.Writer, status int, message, source string) {
	writeErrorWithSourceHeaders(w, status, message, source,
		map[string]string{shouldRetryHeader: "false"})
}

// writeRetryableError reports a failure that happened BEFORE any provider was
// dispatched. Nothing ran and nothing was billed, so re-sending — here or on
// another domain — costs nothing and is the right thing for a client to do.
func writeRetryableError(w io.Writer, status int, message string) {
	writeErrorWithSourceHeaders(w, status, message, "router",
		map[string]string{shouldRetryHeader: "true"})
}

func writeClassifiedOpenAIError(w io.Writer, status int, message string, err error) {
	if isClientInputError(err) {
		writeError(w, status, message)
		return
	}
	writeProviderError(w, status, message)
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
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: %s\r\n",
		status, statusText(status), len(body), responseConnection(w))
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
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n",
		status, statusText(status), len(body), responseConnection(w))
	w.Write(body)
}

func orNilString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func writeJSONResponse(w io.Writer, status int, body []byte) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n",
		status, statusText(status), len(body), responseConnection(w))
	w.Write(body)
}

func writeJSONResponseWithHeaders(w io.Writer, status int, body []byte, headers map[string]string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n",
		status, statusText(status), len(body))
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := headers[name]
		if name != "" && value != "" && !strings.ContainsAny(name+value, "\r\n") {
			fmt.Fprintf(w, "%s: %s\r\n", name, value)
		}
	}
	fmt.Fprintf(w, "Connection: %s\r\n\r\n", responseConnection(w))
	w.Write(body)
}

func writeResponseHead(w io.Writer, status int, contentType string) error {
	if contentType == "" {
		contentType = "text/event-stream"
	}
	_, err := fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\nTransfer-Encoding: chunked\r\nContent-Type: %s\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nConnection: %s\r\n\r\n",
		status, statusText(status), contentType, responseConnection(w))
	return err
}

type responseKeepAliveController interface {
	ResponseKeepAlive() bool
	DisableResponseReuse()
}

func responseKeepAlive(w io.Writer) bool {
	controller, ok := w.(responseKeepAliveController)
	return ok && controller.ResponseKeepAlive()
}

func responseConnection(w io.Writer) string {
	if responseKeepAlive(w) {
		return "keep-alive"
	}
	return "close"
}

func disableResponseReuse(w io.Writer) {
	if controller, ok := w.(responseKeepAliveController); ok {
		controller.DisableResponseReuse()
	}
}

func statusText(status int) string {
	switch status {
	case 200:
		return "OK"
	case 202:
		return "Accepted"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 413:
		return "Payload Too Large"
	case 404:
		return "Not Found"
	case 409:
		return "Conflict"
	case 410:
		return "Gone"
	case 429:
		return "Too Many Requests"
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
	w                    io.Writer
	mu                   sync.Mutex
	requireCleanComplete bool
	complete             bool
	closed               bool
}

func newChunkedWriter(w io.Writer) *chunkedWriter {
	return &chunkedWriter{w: w, requireCleanComplete: responseKeepAlive(w)}
}

func (c *chunkedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := fmt.Fprintf(c.w, "%x\r\n", len(p)); err != nil {
		return 0, err
	}
	n, err := c.w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return n, err
	}
	if _, err := c.w.Write([]byte("\r\n")); err != nil {
		return n, err
	}
	return n, nil
}

func (c *chunkedWriter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *chunkedWriter) closeLocked() error {
	if c.closed {
		return nil
	}
	c.closed = true
	if c.requireCleanComplete && !c.complete {
		// On a persistent response, absence of an explicit clean-completion
		// signal means the stream may be truncated. Suppress the terminal chunk
		// and make the connection non-reusable so clients observe unexpected EOF.
		if controller, ok := c.w.(responseKeepAliveController); ok {
			controller.DisableResponseReuse()
		}
		return nil
	}
	_, err := c.w.Write([]byte("0\r\n\r\n"))
	return err
}

// Complete writes the terminal zero chunk. Callers must use it only after the
// upstream stream and all local transforms have ended successfully.
func (c *chunkedWriter) Complete() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.complete = true
	err := c.closeLocked()
	if err != nil {
		if controller, ok := c.w.(responseKeepAliveController); ok {
			controller.DisableResponseReuse()
		}
	}
	return err
}

// Abort leaves the chunked message deliberately incomplete and prevents this
// connection from carrying another response.
func (c *chunkedWriter) Abort() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	disableResponseReuse(c.w)
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
// shape we surface the upstream status and scrubbed, truncated body so callers
// get the real reason — e.g. an Anthropic 400 validation error — instead of an
// opaque "provider error". Anything we can't classify stays a generic 502.
func upstreamErrorResponse(err error) (int, string) {
	if err == nil {
		return 502, "provider error"
	}
	var aerr *adapter.AdapterError
	if asAdapterErr(err, &aerr) {
		return aerr.Status, aerr.Message
	}
	if message, ok := clientInputErrorMessage(err); ok {
		return 400, message
	}
	s := err.Error()
	if i := strings.LastIndex(s, "http "); i >= 0 {
		rest := s[i+len("http "):]
		if c := strings.IndexByte(rest, ':'); c > 0 {
			if code, e := strconv.Atoi(strings.TrimSpace(rest[:c])); e == nil && code >= 400 && code < 600 {
				body := strings.TrimSpace(rest[c+1:])
				body = upstreamAPIKeyPattern.ReplaceAllString(body, "sk-***")
				body = upstreamBearerPattern.ReplaceAllString(body, "Bearer ***")
				if len(body) > 1200 {
					body = body[:1200]
				}
				if body != "" {
					return code, fmt.Sprintf("upstream http %d: %s", code, body)
				}
			}
		}
	}
	return 502, "provider error"
}

type clientInputError interface {
	ClientInputMessage() string
}

func isClientInputError(err error) bool {
	_, ok := clientInputErrorMessage(err)
	return ok
}

func clientInputErrorMessage(err error) (string, bool) {
	var marker clientInputError
	if !errors.As(err, &marker) {
		return "", false
	}
	message := strings.TrimSpace(marker.ClientInputMessage())
	return message, message != ""
}

func failureReason(err error) string {
	if isClientInputError(err) {
		return "client_error"
	}
	return "provider_error"
}

// writeAnthropicError writes the Anthropic-shaped error envelope the
// Messages API uses: {"type":"error","error":{"type":...,"message":...}}.
func writeAnthropicError(w io.Writer, status int, message string) {
	writeAnthropicErrorWithSource(w, status, message, "router")
}

func writeAnthropicProviderError(w io.Writer, status int, message string) {
	writeAnthropicErrorWithSource(w, status, message, "provider")
}

func writeClassifiedAnthropicError(w io.Writer, status int, message string, err error) {
	if isClientInputError(err) {
		writeAnthropicErrorWithSource(w, status, message, "router")
		return
	}
	writeAnthropicProviderError(w, status, message)
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
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: %s\r\n",
		status, statusText(status), len(body), responseConnection(w))
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
