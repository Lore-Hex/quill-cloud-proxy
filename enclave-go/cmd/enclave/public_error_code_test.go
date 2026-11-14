package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/auth"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestPublicErrorCodesAreSafeAndStable(t *testing.T) {
	for _, tc := range []struct {
		status        int
		message, code string
	}{
		{400, "invalid JSON", "invalid_json"},
		{400, "could not read request", "request_read_failed"},
		{400, "private provider diagnostic", "invalid_request"},
		{413, "request body too large", "request_body_too_large"},
		{431, "request headers too large", "request_headers_too_large"},
		{503, "unavailable", "service_unavailable"},
	} {
		var out bytes.Buffer
		writeError(&out, tc.status, tc.message)
		_, body, _ := strings.Cut(out.String(), "\r\n\r\n")
		var wire struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(body), &wire); err != nil {
			t.Fatal(err)
		}
		if wire.Error.Code != tc.code {
			t.Fatalf("code = %q want %q", wire.Error.Code, tc.code)
		}
	}
}

func TestUploadErrorsHaveReasonCodesBeforeAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name, headers, body, code string
	}{
		{"incomplete", "Content-Length: 100\r\n", "{", "incomplete_request_body"},
		{"ambiguous", "Content-Length: 2\r\nTransfer-Encoding: chunked\r\n", "{}", "ambiguous_request_framing"},
		{"chunked", "Transfer-Encoding: chunked\r\n", "0\r\n\r\n", "unsupported_transfer_encoding"},
		{"too_large", "Content-Length: 10485761\r\n", "", "request_body_too_large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := trustedrouter.New("https://billing.invalid", "fixture", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("malformed upload reached billing")
				return nil, fmt.Errorf("unexpected billing request")
			})})
			conn := newScriptedConn("POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer fixture\r\n"+tc.headers+"\r\n"+tc.body, nil)
			serveOne(t.Context(), conn, auth.New(nil), &fakeStreamingLLM{}, nil, nil, gateway, nil)
			_, body, _ := strings.Cut(conn.writes.String(), "\r\n\r\n")
			var wire struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(body), &wire); err != nil {
				t.Fatalf("invalid error response: %v", err)
			}
			if wire.Error.Code != tc.code {
				t.Fatalf("code = %q want %q", wire.Error.Code, tc.code)
			}
		})
	}
}
