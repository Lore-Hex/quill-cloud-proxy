package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

func requireBearerCORS(t *testing.T, response *http.Response) {
	t.Helper()
	if got := response.Header.Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != "*" {
		t.Fatalf("allow origin = %v", got)
	}
	if response.Header.Get("Access-Control-Allow-Credentials") != "" || response.Header.Get("Set-Cookie") != "" {
		t.Fatal("API CORS must not enable cookie credentials")
	}
	for _, header := range []string{"X-Request-ID", "Request-ID", "Retry-After", "X-Should-Retry", "X-Inference-Receipt"} {
		if !strings.Contains(response.Header.Get("Access-Control-Expose-Headers"), header) {
			t.Errorf("browser cannot read %s", header)
		}
	}
}

func TestBearerCORSPreflightBeforeAuthentication(t *testing.T) {
	gateway := untouchedControlPlane(t)
	for _, host := range []string{"api.trustedrouter.com", "api.confidential.trustedrouter.com"} {
		for _, path := range []string{
			"/v1/chat/completions", "/v1/responses", "/v1/messages", "/v1/embeddings",
			"/v1/images", "/v1/audio/speech", "/v1/audio/transcriptions",
			"/v1/responses/input_tokens", "/v1/key",
		} {
			request := fmt.Sprintf("OPTIONS %s HTTP/1.1\r\nHost: %s\r\nOrigin: https://chat.example\r\n"+
				"Access-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: authorization,content-type,idempotency-key,x-stainless-os\r\n\r\n", path, host)
			conn := newScriptedConn(request, nil)
			serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)
			response, body := readRawHTTPResponse(t, conn.writes.Bytes())
			if response.StatusCode != 204 || len(body) != 0 || response.Header.Get("Content-Length") != "" {
				t.Fatalf("%s %s: invalid preflight %d %s", host, path, response.StatusCode, body)
			}
			requireBearerCORS(t, response)
			for header, want := range map[string]string{
				"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
				"Access-Control-Allow-Headers": "Authorization, Content-Type, *",
				"Access-Control-Max-Age":       "600",
			} {
				if got := response.Header.Get(header); got != want {
					t.Fatalf("%s = %q; want %q", header, got, want)
				}
			}
		}
	}
}

func TestBearerCORSDoesNotAuthenticateCookies(t *testing.T) {
	gateway := untouchedControlPlane(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses", "/v1/messages", "/v1/key"} {
		method := "POST"
		if path == "/v1/key" {
			method = "GET"
		}
		request := method + " " + path + " HTTP/1.1\r\nHost: api.trustedrouter.com\r\n" +
			"Origin: https://chat.example\r\nCookie: session=valid-looking-session\r\nContent-Length: 0\r\n\r\n"
		conn := newScriptedConn(request, nil)
		serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)
		response, body := readRawHTTPResponse(t, conn.writes.Bytes())
		if response.StatusCode != 401 {
			t.Fatalf("%s must still require a key: %d %s", path, response.StatusCode, body)
		}
		requireBearerCORS(t, response)
	}
}

func TestBearerCORSEndToEndResponses(t *testing.T) {
	for _, test := range []struct {
		name, path, body, token, want string
		status                        int
		provider                      llm.Client
	}{
		{"chat JSON", "/v1/chat/completions", `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":false}`, "browser-key", `Hello world`, 200, &fakeStreamingLLM{}},
		{"chat SSE", "/v1/chat/completions", `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`, "browser-key", "data: [DONE]", 200, &fakeStreamingLLM{}},
		{"responses JSON", "/v1/responses", `{"model":"test-model","input":"hello","stream":false}`, "browser-key", `Hello world`, 200, &fakeStreamingLLM{}},
		{"responses SSE", "/v1/responses", `{"model":"test-model","input":"hello","stream":true}`, "browser-key", "response.completed", 200, &fakeStreamingLLM{}},
		{"invalid key", "/v1/chat/completions", `{}`, "invalid", "Invalid API key", 401, nil},
		{"invalid JSON", "/v1/chat/completions", `{`, "browser-key", "invalid JSON", 400, nil},
		{"provider error", "/v1/chat/completions", `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`, "browser-key", "error", 502, &failingStreamingLLM{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			_ = peer.SetDeadline(time.Now().Add(10 * time.Second))
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				serveOne(context.Background(), server, registryForBearer("browser-key"), test.provider, nil, nil, nil, nil)
			}()
			_, err := fmt.Fprintf(peer, "POST %s HTTP/1.1\r\nHost: api.trustedrouter.com\r\n"+
				"Origin: https://chat.example\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n"+
				"Connection: close\r\nContent-Length: %d\r\n\r\n%s", test.path, test.token, len(test.body), test.body)
			if err != nil {
				t.Fatal(err)
			}
			response, body := readHTTPResponseBody(t, bufio.NewReader(peer))
			if response.StatusCode != test.status || !strings.Contains(body, test.want) {
				t.Fatalf("status=%d body=%s", response.StatusCode, body)
			}
			requireBearerCORS(t, response)
			<-finished
		})
	}
}

func TestBearerCORSConfidentialPolicyStillEnforced(t *testing.T) {
	conn := newScriptedConn("POST /v1/chat/completions HTTP/1.1\r\nHost: api.confidential.trustedrouter.com\r\n"+
		"Origin: https://chat.example\r\nContent-Length: 0\r\n\r\n", nil)
	serveOne(context.Background(), conn, nil, nil, nil, nil, untouchedControlPlane(t), nil)
	response, _ := readRawHTTPResponse(t, conn.writes.Bytes())
	if response.StatusCode != 400 {
		t.Fatalf("confidential validation was bypassed: %d", response.StatusCode)
	}
	requireBearerCORS(t, response)
}

func TestBearerCORSKeepAliveAndScope(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		request := strings.ReplaceAll(browserPreflight(path, "api.trustedrouter.com"), "Request-Method: GET", "Request-Method: POST")
		request += "POST " + path + " HTTP/1.1\r\nHost: api.trustedrouter.com\r\nContent-Length: 0\r\n\r\n"
		request += "GET /health HTTP/1.1\r\nHost: api.trustedrouter.com\r\nConnection: close\r\n\r\n"
		conn := newScriptedConn(request, nil)
		serveOne(context.Background(), conn, nil, nil, nil, nil, untouchedControlPlane(t), nil)
		reader := bufio.NewReader(bytes.NewReader(conn.writes.Bytes()))
		for i, status := range []int{204, 401, 200} {
			response, _ := readHTTPResponseBody(t, reader)
			if response.StatusCode != status {
				t.Fatalf("response %d: %d, want %d", i, response.StatusCode, status)
			}
			if i < 2 {
				requireBearerCORS(t, response)
			} else if response.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("CORS state leaked to the next request")
			}
		}
	}
}

func TestBearerCORSBillingDenialHeaders(t *testing.T) {
	conn := newScriptedConn("", nil)
	stats := &responseStatsConn{Conn: conn}
	stats.BeginRequest(testRequestLogID)
	stats.SetBrowserCORS(true)
	writeErrorWithSourceHeaders(stats, 429, "slow down", "router", map[string]string{
		"Retry-After": "30", shouldRetryHeader: "true",
	})
	response, _ := readRawHTTPResponse(t, conn.writes.Bytes())
	requireBearerCORS(t, response)
	if response.StatusCode != 429 || response.Header.Get("Retry-After") != "30" || response.Header.Get(shouldRetryHeader) != "true" {
		t.Fatalf("billing headers changed: %#v", response)
	}
}

func TestBearerCORSWriteFraming(t *testing.T) {
	first := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
	conn := newScriptedConn("", nil)
	stats := &responseStatsConn{Conn: conn}
	stats.BeginRequest(testRequestLogID)
	stats.SetBrowserCORS(true)
	n, err := stats.Write(first)
	if err != nil || n != len(first) {
		t.Fatalf("caller byte count changed: %d %v", n, err)
	}
	status, count := stats.Snapshot()
	if status != 200 || count != conn.writes.Len() {
		t.Fatalf("wire statistics changed: %d %d", status, count)
	}
	response, body := readRawHTTPResponse(t, conn.writes.Bytes())
	requireBearerCORS(t, response)
	if string(body) != "{}" {
		t.Fatalf("body changed: %s", body)
	}
	for _, chunks := range [][]string{
		{"HTTP/1.1 200 OK", "\r\nContent-Length: 0\r\n\r\n"},
		{"not HTTP", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
	} {
		conn := newScriptedConn("", nil)
		stats := &responseStatsConn{Conn: conn}
		stats.BeginRequest(testRequestLogID)
		stats.SetBrowserCORS(true)
		for _, chunk := range chunks {
			if _, err := io.WriteString(stats, chunk); err != nil {
				t.Fatal(err)
			}
		}
		if conn.writes.String() != strings.Join(chunks, "") {
			t.Fatal("CORS injection corrupted partial/non-HTTP writes")
		}
	}
}
