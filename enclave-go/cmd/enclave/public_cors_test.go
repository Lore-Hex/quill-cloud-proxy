package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/attestation"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

// browserPreflight is what a browser sends before a cross-origin GET that
// carries an API key and SDK telemetry headers.
func browserPreflight(target, host string) string {
	return "OPTIONS " + target + " HTTP/1.1\r\nHost: " + host + "\r\n" +
		"Origin: https://app.example\r\n" +
		"Access-Control-Request-Method: GET\r\n" +
		"Access-Control-Request-Headers: authorization, x-stainless-os\r\n\r\n"
}

func untouchedControlPlane(t *testing.T) *trustedrouter.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a preflight reached the control plane: %s %s", r.Method, r.URL.RequestURI())
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	return trustedrouter.New(server.URL, "internal", server.Client())
}

func TestServeOnePublicPreflightAnswersBrowsers(t *testing.T) {
	gateway := untouchedControlPlane(t)
	for _, host := range []string{"api.trustedrouter.com", "api.confidential.trustedrouter.com"} {
		for _, target := range []string{
			"/v1/models",
			"/v1/models?include=endpoints",
			"/v1/models/openai/gpt-4o/endpoints",
			"/v1/images/models",
			"/v1/images/models/google/gemini-3.1-flash-image/endpoints",
			"/attestation",
			"/attestation?nonce=00ff",
		} {
			conn := newScriptedConn(browserPreflight(target, host), nil)
			serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)
			resp, body := readRawHTTPResponse(t, conn.writes.Bytes())
			if resp.StatusCode != http.StatusNoContent || len(body) != 0 {
				t.Fatalf("%s %s preflight = %d %s", host, target, resp.StatusCode, body)
			}
			for name, want := range map[string]string{
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET, OPTIONS",
				"Access-Control-Allow-Headers": "Authorization, *",
				"Access-Control-Max-Age":       "600",
			} {
				if got := resp.Header.Get(name); got != want {
					t.Errorf("%s %s %s = %q, want %q", host, target, name, got, want)
				}
			}
			if _, present := resp.Header["Content-Length"]; present {
				t.Errorf("%s %s 204 carries Content-Length", host, target)
			}
			if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
				t.Errorf("%s %s Access-Control-Allow-Credentials = %q", host, target, got)
			}
		}
	}
}

// The preflight policy is only for anonymous GET routes. Inference and every
// non-public shape still go through the authentication gate with no CORS
// headers, exactly as before.
func TestServeOnePreflightLeavesOtherRoutesUnchanged(t *testing.T) {
	gateway := untouchedControlPlane(t)
	for _, target := range []string{
		"/v1/chat/completions",
		"/v1/responses",
		"/v1/messages",
		"/v1/key",
		"/v1/models/openai/gpt-4o/extra/endpoints",
		"/v1/models/../x/endpoints",
		"/receipt-key",
	} {
		conn := newScriptedConn(browserPreflight(target, "api.trustedrouter.com"), nil)
		serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)
		resp, body := readRawHTTPResponse(t, conn.writes.Bytes())
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s preflight = %d %s, want the unchanged 401", target, resp.StatusCode, body)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s gained Access-Control-Allow-Origin %q", target, got)
		}
	}
}

func TestServeOnePreflightKeepsPersistentConnectionUsable(t *testing.T) {
	t.Setenv("QUILL_KEEPALIVE", "on")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"trustedrouter/auto"}]}`)
	}))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())

	conn := newScriptedConn(
		browserPreflight("/v1/models", "api.trustedrouter.com")+
			"GET /v1/models HTTP/1.1\r\nHost: api.trustedrouter.com\r\nAuthorization: Bearer sk-tr-v1-not-checked\r\nConnection: close\r\n\r\n",
		nil,
	)
	serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)

	reader := bufio.NewReader(bytes.NewReader(conn.writes.Bytes()))
	preflight, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read preflight: %v; raw=%s", err, conn.writes.String())
	}
	_ = preflight.Body.Close()
	if preflight.StatusCode != http.StatusNoContent || preflight.Close {
		t.Fatalf("preflight status=%d close=%v", preflight.StatusCode, preflight.Close)
	}
	get, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read GET after preflight: %v; raw=%s", err, conn.writes.String())
	}
	body, _ := io.ReadAll(get.Body)
	if get.StatusCode != http.StatusOK || !strings.Contains(string(body), "trustedrouter/auto") {
		t.Fatalf("GET after preflight = %d %s", get.StatusCode, body)
	}
	if get.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("GET after preflight lacks CORS: %#v", get.Header)
	}
}

func TestServeOnePublicCatalogErrorsAreReadableCrossOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "private upstream detail", http.StatusInternalServerError)
	}))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())

	for _, route := range []string{"/v1/models", "/v1/models?include=endpoints", "/v1/models/openai/gpt-4o/endpoints"} {
		conn := newScriptedConn("GET "+route+" HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n", nil)
		serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)
		resp, body := readRawHTTPResponse(t, conn.writes.Bytes())
		if resp.StatusCode != http.StatusServiceUnavailable || bytes.Contains(body, []byte("private upstream detail")) {
			t.Fatalf("%s = %d %s", route, resp.StatusCode, body)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "*" || resp.Header.Get(shouldRetryHeader) != "true" {
			t.Fatalf("%s error headers = %#v", route, resp.Header)
		}
	}
}

func TestServeOneAttestationIsReadableCrossOrigin(t *testing.T) {
	old := getAttestation
	defer func() { getAttestation = old }()
	exporter := bytes.Repeat([]byte{0x42}, enclavetls.ExporterLength)

	getAttestation = func(_ context.Context, _, _, nonce, _, _ []byte) ([]byte, error) {
		return []byte(fmt.Sprintf("doc-for-%x", nonce)), nil
	}
	for _, target := range []string{"/attestation", "/attestation?nonce=00ff"} {
		conn := &attestationExporterConn{
			scriptedConn: newScriptedConn("GET "+target+" HTTP/1.1\r\nHost: api.trustedrouter.com\r\nOrigin: https://app.example\r\n\r\n", []byte("leaf")),
			exporter:     exporter,
		}
		serveOne(context.Background(), conn, nil, nil, nil, []byte("devices"), nil, nil)
		resp, body := readRawHTTPResponse(t, conn.writes.Bytes())
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "doc-for-") {
			t.Fatalf("%s = %d %s", target, resp.StatusCode, body)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "*" || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s headers = %#v", target, resp.Header)
		}
	}

	// Failures are readable too: issuer outage and a missing channel binding.
	getAttestation = func(context.Context, []byte, []byte, []byte, []byte, []byte) ([]byte, error) {
		return nil, fmt.Errorf("%w: private issuer evidence", attestation.ErrIssuerUnavailable)
	}
	issuerConn := &attestationExporterConn{
		scriptedConn: newScriptedConn("GET /attestation HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n", []byte("leaf")),
		exporter:     exporter,
	}
	serveOne(context.Background(), issuerConn, nil, nil, nil, []byte("devices"), nil, nil)
	noExporterConn := newScriptedConn("GET /attestation HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n", []byte("leaf"))
	serveOne(context.Background(), noExporterConn, nil, nil, nil, []byte("devices"), nil, nil)
	for name, raw := range map[string][]byte{
		"issuer unavailable": issuerConn.writes.Bytes(),
		"no exporter":        noExporterConn.writes.Bytes(),
	} {
		resp, body := readRawHTTPResponse(t, raw)
		if resp.StatusCode != http.StatusServiceUnavailable || bytes.Contains(body, []byte("private issuer evidence")) {
			t.Fatalf("%s = %d %s", name, resp.StatusCode, body)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s lacks CORS: %#v", name, resp.Header)
		}
	}
}

func TestReadRequestCombinesAcceptEncodingFields(t *testing.T) {
	request := "GET /v1/models HTTP/1.1\r\nHost: api.trustedrouter.com\r\nAccept-Encoding: br\r\naccept-encoding: gzip;q=0.5\r\n\r\n"
	_, _, _, _, attribution, _, err := readRequest(bufio.NewReader(strings.NewReader(request)))
	if err != nil {
		t.Fatal(err)
	}
	if attribution.acceptEncoding != "br, gzip;q=0.5" || !acceptsGzip(attribution.acceptEncoding) {
		t.Fatalf("acceptEncoding = %q", attribution.acceptEncoding)
	}
}
