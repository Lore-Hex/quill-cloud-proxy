package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func TestKeepAliveTwoSequentialJSONRequestsOnOneConnection(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	bearer := "keepalive-json"
	network, addr, tlsConfig := startTLSServeOneLoopback(t, registryForBearer(bearer), &fakeStreamingLLM{})
	conn, reader := dialServeOneTLS(t, network, addr, tlsConfig)
	defer conn.Close()

	for requestNumber := 1; requestNumber <= 2; requestNumber++ {
		writeAuthorizedGET(t, conn, bearer, "/not-found")
		response, body := readHTTPResponseBody(t, reader)
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("response %d status=%d body=%s", requestNumber, response.StatusCode, body)
		}
		if response.Close {
			t.Fatalf("response %d unexpectedly requested connection close", requestNumber)
		}
	}
}

func TestKeepAliveServeLoopOverPipe(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	bearer := "keepalive-pipe"
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go serveOne(context.Background(), server, registryForBearer(bearer), &fakeStreamingLLM{}, nil, nil, nil, nil)
	reader := bufio.NewReader(client)

	for requestNumber := 1; requestNumber <= 2; requestNumber++ {
		writeAuthorizedGET(t, client, bearer, "/not-found")
		response, body := readHTTPResponseBody(t, reader)
		if response.StatusCode != http.StatusNotFound || response.Close {
			t.Fatalf("response %d status=%d close=%t body=%s", requestNumber, response.StatusCode, response.Close, body)
		}
	}
}

func TestKeepAliveChunkedStreamThenJSONOverPipe(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	bearer := "keepalive-pipe-stream"
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go serveOne(context.Background(), server, registryForBearer(bearer), &fakeStreamingLLM{}, nil, nil, nil, nil)
	reader := bufio.NewReader(client)

	writeStreamingChatRequest(t, client, bearer)
	streamResponse, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read stream response: %v", err)
	}
	streamBody, err := io.ReadAll(streamResponse.Body)
	streamResponse.Body.Close()
	if err != nil || !bytes.Contains(streamBody, []byte("data: [DONE]")) {
		t.Fatalf("read chunked stream err=%v body=%s", err, streamBody)
	}

	writeAuthorizedGET(t, client, bearer, "/not-found")
	response, body := readHTTPResponseBody(t, reader)
	if response.StatusCode != http.StatusNotFound || response.Close {
		t.Fatalf("JSON response status=%d close=%t body=%s", response.StatusCode, response.Close, body)
	}
}

func TestKeepAliveTruncatedStreamOverPipeIsNotTerminated(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	bearer := "keepalive-pipe-truncated"
	server, pipeClient := net.Pipe()
	conn := &recordingReadConn{Conn: pipeClient}
	t.Cleanup(func() { _ = conn.Close() })
	go serveOne(context.Background(), server, registryForBearer(bearer), keepAliveTruncatedLLM{}, nil, nil, nil, nil)
	reader := bufio.NewReader(conn)

	writeStreamingChatRequest(t, conn, bearer)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read stream response: %v", err)
	}
	_, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if !errors.Is(readErr, io.ErrUnexpectedEOF) {
		t.Fatalf("stream read error=%v, want unexpected EOF", readErr)
	}
	if wire := conn.ReadBytes(); bytes.HasSuffix(wire, []byte("0\r\n\r\n")) {
		t.Fatalf("truncated stream ended with a terminal chunk: %q", wire)
	}
}

func TestKeepAliveStreamThenJSONUsesNetHTTPChunkDecoderAndSameConnection(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	bearer := "keepalive-stream"
	network, addr, tlsConfig := startTLSServeOneLoopback(t, registryForBearer(bearer), &fakeStreamingLLM{})
	client := newKeepAliveHTTPClient(t, network, addr, tlsConfig)

	requestBody := `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`
	request, err := http.NewRequest(http.MethodPost, "https://test.quill.local/v1/chat/completions", strings.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("stream request: %v", err)
	}
	streamBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("net/http decode chunked stream: %v", err)
	}
	if len(response.TransferEncoding) != 1 || response.TransferEncoding[0] != "chunked" {
		t.Fatalf("TransferEncoding=%v, want chunked", response.TransferEncoding)
	}
	if !bytes.Contains(streamBody, []byte("data: [DONE]")) {
		t.Fatalf("stream body missing DONE event: %s", streamBody)
	}

	var secondConnection httptrace.GotConnInfo
	secondRequest, err := http.NewRequest(http.MethodGet, "https://test.quill.local/not-found", nil)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest.Header.Set("Authorization", "Bearer "+bearer)
	secondRequest = secondRequest.WithContext(httptrace.WithClientTrace(secondRequest.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { secondConnection = info },
	}))
	secondResponse, err := client.Do(secondRequest)
	if err != nil {
		t.Fatalf("JSON request after stream: %v", err)
	}
	secondBody, readErr := io.ReadAll(secondResponse.Body)
	secondResponse.Body.Close()
	if readErr != nil {
		t.Fatalf("read JSON response: %v", readErr)
	}
	if secondResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("second status=%d body=%s", secondResponse.StatusCode, secondBody)
	}
	if !secondConnection.Reused {
		t.Fatal("net/http opened a new connection after the completed stream")
	}
}

func TestKeepAliveTruncatedUpstreamClosesWithoutTerminalChunk(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	bearer := "keepalive-truncated"
	network, addr, tlsConfig := startTLSServeOneLoopback(t, registryForBearer(bearer), keepAliveTruncatedLLM{})
	tlsConn, _ := dialServeOneTLS(t, network, addr, tlsConfig)
	conn := &recordingReadConn{Conn: tlsConn}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	requestBody := `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`
	_, err := fmt.Fprintf(conn,
		"POST /v1/chat/completions HTTP/1.1\r\nHost: test.quill.local\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer, len(requestBody), requestBody,
	)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response head: %v", err)
	}
	decoded, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr == nil {
		t.Fatalf("truncated stream decoded without error: %s", decoded)
	}
	if !errors.Is(readErr, io.ErrUnexpectedEOF) {
		t.Fatalf("stream read error=%v, want unexpected EOF", readErr)
	}
	if wire := conn.ReadBytes(); bytes.HasSuffix(wire, []byte("0\r\n\r\n")) {
		t.Fatalf("truncated stream ended with a terminal chunk: %q", wire)
	}
}

func TestKeepAliveRejectsContentLengthWithTransferEncoding(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	network, addr, tlsConfig := startTLSServeOneLoopback(t, registryForBearer("unused"), &fakeStreamingLLM{})
	conn, reader := dialServeOneTLS(t, network, addr, tlsConfig)
	defer conn.Close()

	_, err := io.WriteString(conn,
		"POST /v1/chat/completions HTTP/1.1\r\nHost: test.quill.local\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"+
			"GET /health HTTP/1.1\r\nHost: test.quill.local\r\n\r\n",
	)
	if err != nil {
		t.Fatalf("write ambiguous request: %v", err)
	}
	response, body := readHTTPResponseBody(t, reader)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	if !response.Close {
		t.Fatal("ambiguous framing response did not require connection close")
	}
	expectConnectionClosed(t, conn, reader)
}

func TestKeepAliveIdleTimeoutClosesConnection(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	t.Setenv("QUILL_KEEPALIVE_IDLE_TIMEOUT", "100ms")
	bearer := "keepalive-idle"
	network, addr, tlsConfig := startTLSServeOneLoopback(t, registryForBearer(bearer), &fakeStreamingLLM{})
	conn, reader := dialServeOneTLS(t, network, addr, tlsConfig)
	defer conn.Close()

	writeAuthorizedGET(t, conn, bearer, "/not-found")
	response, body := readHTTPResponseBody(t, reader)
	if response.StatusCode != http.StatusNotFound || response.Close {
		t.Fatalf("status=%d close=%t body=%s", response.StatusCode, response.Close, body)
	}
	expectConnectionClosed(t, conn, reader)
}

func TestKeepAliveKillSwitchClosesEveryResponse(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "off")
	network, addr, tlsConfig := startTLSServeOneLoopback(t, registryForBearer("unused"), &fakeStreamingLLM{})
	conn, reader := dialServeOneTLS(t, network, addr, tlsConfig)
	defer conn.Close()

	if _, err := io.WriteString(conn, "GET /health HTTP/1.1\r\nHost: test.quill.local\r\n\r\n"); err != nil {
		t.Fatalf("write health request: %v", err)
	}
	response, body := readHTTPResponseBody(t, reader)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	if !response.Close {
		t.Fatal("QUILL_KEEPALIVE=off did not restore Connection: close")
	}
	expectConnectionClosed(t, conn, reader)
}

func TestKeepAliveKillSwitchClosesStreamingResponseOverPipe(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "off")
	bearer := "keepalive-off-stream"
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go serveOne(context.Background(), server, registryForBearer(bearer), &fakeStreamingLLM{}, nil, nil, nil, nil)
	reader := bufio.NewReader(client)

	writeStreamingChatRequest(t, client, bearer)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read stream response: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil || !bytes.Contains(body, []byte("data: [DONE]")) {
		t.Fatalf("read legacy stream err=%v body=%s", readErr, body)
	}
	if !response.Close {
		t.Fatal("QUILL_KEEPALIVE=off streamed response did not advertise close")
	}
	expectConnectionClosed(t, client, reader)
}

func TestKeepAliveHonorsRequestCloseAndHTTP10(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	for _, request := range []string{
		"GET /health HTTP/1.1\r\nHost: test.quill.local\r\nConnection: close\r\n\r\n",
		"GET /health HTTP/1.0\r\nHost: test.quill.local\r\n\r\n",
	} {
		network, addr, tlsConfig := startTLSServeOneLoopback(t, registryForBearer("unused"), &fakeStreamingLLM{})
		conn, reader := dialServeOneTLS(t, network, addr, tlsConfig)
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatalf("write request: %v", err)
		}
		response, body := readHTTPResponseBody(t, reader)
		if response.StatusCode != http.StatusOK || !response.Close {
			t.Fatalf("request=%q status=%d close=%t body=%s", request, response.StatusCode, response.Close, body)
		}
		expectConnectionClosed(t, conn, reader)
		conn.Close()
	}
}

func TestKeepAliveMaxRequestsAdvertisesCloseOnFinalResponse(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	t.Setenv("QUILL_KEEPALIVE_MAX_REQUESTS", "2")
	bearer := "keepalive-max"
	network, addr, tlsConfig := startTLSServeOneLoopback(t, registryForBearer(bearer), &fakeStreamingLLM{})
	conn, reader := dialServeOneTLS(t, network, addr, tlsConfig)
	defer conn.Close()

	writeAuthorizedGET(t, conn, bearer, "/not-found")
	first, _ := readHTTPResponseBody(t, reader)
	if first.Close {
		t.Fatal("first response closed before configured request cap")
	}
	writeAuthorizedGET(t, conn, bearer, "/not-found")
	second, _ := readHTTPResponseBody(t, reader)
	if !second.Close {
		t.Fatal("final response at configured request cap did not advertise close")
	}
	expectConnectionClosed(t, conn, reader)
}

func TestRequestFramingRefusals(t *testing.T) {
	for name, raw := range map[string]string{
		"content length and transfer encoding": "POST / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
		"chunked request body":                 "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
		"duplicate content length":             "POST / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
		"whitespace before header colon":       "POST / HTTP/1.1\r\nContent-Length : 0\r\n\r\n",
		"bare LF line endings":                 "POST / HTTP/1.1\nContent-Length: 0\n\n",
		"signed content length":                "POST / HTTP/1.1\r\nContent-Length: +3\r\n\r\nabc",
		"control byte in header value":         "POST / HTTP/1.1\r\nX-Test: before\x00after\r\n\r\n",
		"tab separated request line":           "POST\t/\tHTTP/1.1\r\nContent-Length: 0\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, _, _, _, err := readRequest(bufio.NewReader(strings.NewReader(raw)))
			if err == nil {
				t.Fatal("ambiguous or unsupported framing was accepted")
			}
		})
	}
}

func TestKeepAliveConfigPreservesLegacyDefaultsUntilEnabled(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "")
	t.Setenv("QUILL_KEEPALIVE_IDLE_TIMEOUT", "")
	t.Setenv("QUILL_KEEPALIVE_MAX_REQUESTS", "")
	legacy := loadKeepAliveConfig()
	if legacy.mode != keepAliveLegacy || legacy.idleTimeout != requestReadTimeout {
		t.Fatalf("legacy config=%+v, want mode=legacy idle=%s", legacy, requestReadTimeout)
	}

	t.Setenv("QUILL_KEEPALIVE", "on")
	enabled := loadKeepAliveConfig()
	if enabled.mode != keepAliveOn || enabled.idleTimeout != defaultKeepAliveIdleTimeout || enabled.maxRequests != defaultKeepAliveMaxRequests {
		t.Fatalf("enabled defaults=%+v", enabled)
	}
}

func TestKeepAliveLegacyUsesSingleDeadlineBudget(t *testing.T) {
	base := newScriptedConn("", nil)
	deadlines := &requestDeadlineConn{Conn: base}
	reader := bufio.NewReader(deadlines)

	armRequestReadDeadline(deadlines, reader, 1, keepAliveConfig{
		mode:        keepAliveLegacy,
		idleTimeout: requestReadTimeout,
	})
	deadlines.mu.Lock()
	legacyWaitsForFirstByte := deadlines.waitingForRequestByte
	deadlines.mu.Unlock()
	if legacyWaitsForFirstByte {
		t.Fatal("legacy mode split its existing single deadline into idle and header budgets")
	}

	armRequestReadDeadline(deadlines, reader, 1, keepAliveConfig{
		mode:        keepAliveOn,
		idleTimeout: defaultKeepAliveIdleTimeout,
	})
	deadlines.mu.Lock()
	enabledWaitsForFirstByte := deadlines.waitingForRequestByte
	deadlines.mu.Unlock()
	if !enabledWaitsForFirstByte {
		t.Fatal("enabled keep-alive did not arm a distinct idle deadline")
	}
}

func writeAuthorizedGET(t *testing.T, conn io.Writer, bearer, path string) {
	t.Helper()
	if _, err := fmt.Fprintf(conn,
		"GET %s HTTP/1.1\r\nHost: test.quill.local\r\nAuthorization: Bearer %s\r\n\r\n",
		path, bearer,
	); err != nil {
		t.Fatalf("write request: %v", err)
	}
}

func writeStreamingChatRequest(t *testing.T, conn io.Writer, bearer string) {
	t.Helper()
	requestBody := `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`
	if _, err := fmt.Fprintf(conn,
		"POST /v1/chat/completions HTTP/1.1\r\nHost: test.quill.local\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		bearer, len(requestBody), requestBody,
	); err != nil {
		t.Fatalf("write streaming request: %v", err)
	}
}

func newKeepAliveHTTPClient(t *testing.T, network, addr string, tlsConfig *tls.Config) *http.Client {
	t.Helper()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig.Clone(),
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

type keepAliveTruncatedLLM struct{}

func (keepAliveTruncatedLLM) InvokeStreaming(
	_ context.Context,
	_ *types.OpenAIChatRequest,
	_ *types.AnthropicMessagesRequest,
	out io.Writer,
	_ ...llm.InvokeOptions,
) error {
	_, _ = io.WriteString(out, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n")
	return errors.New("upstream disconnected mid-stream")
}

type recordingReadConn struct {
	net.Conn
	mu   sync.Mutex
	read bytes.Buffer
}

func (c *recordingReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		_, _ = c.read.Write(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordingReadConn) ReadBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.read.Bytes()...)
}
