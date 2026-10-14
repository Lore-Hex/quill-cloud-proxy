package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/trustedrouter"
)

func TestServeOnePublicModelsIsAnonymousOnAttestedOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("control-plane path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-TrustedRouter-Internal-Token") != "" {
			t.Fatalf("public catalog received credentials: %#v", r.Header)
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"trustedrouter/auto"}]}`)
	}))
	defer server.Close()

	conn := newScriptedConn("GET /v1/models HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n", nil)
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)

	out := conn.writes.String()
	if !strings.Contains(out, "HTTP/1.1 200 OK") {
		t.Fatalf("response = %s", out)
	}
	if !strings.Contains(out, "Access-Control-Allow-Origin: *") {
		t.Fatalf("missing public CORS header: %s", out)
	}
	if got := httpBody(t, out); !strings.Contains(got, "trustedrouter/auto") {
		t.Fatalf("body = %s", got)
	}
}

func TestServeOnePublicModelsFiltersImageOutputModalities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[`+
			`{"id":"text-only","architecture":{"output_modalities":["text"]}},`+
			`{"id":"image-only","architecture":{"output_modalities":["image"]}}]}`)
	}))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	conn := newScriptedConn(
		"GET /v1/models?output_modalities=image HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n",
		nil,
	)

	serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)

	body := httpBody(t, conn.writes.String())
	if !strings.Contains(body, "image-only") || strings.Contains(body, "text-only") {
		t.Fatalf("filtered model catalog = %s", body)
	}
}

func TestServeOnePublicImageCatalogsAreAnonymousOnAttestedOrigin(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-TrustedRouter-Internal-Token") != "" {
			t.Fatalf("public image catalog received credentials: %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/endpoints") {
			_, _ = io.WriteString(w, `{"id":"google/gemini-3.1-flash-image","endpoints":[{"provider_slug":"google-ai-studio"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"google/gemini-3.1-flash-image"}]}`)
	}))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())

	for _, route := range []string{
		"/v1/images/models",
		"/v1/images/models/google/gemini-3.1-flash-image/endpoints",
	} {
		conn := newScriptedConn("GET "+route+" HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n", nil)
		serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)
		if !strings.Contains(conn.writes.String(), "HTTP/1.1 200 OK") {
			t.Fatalf("%s response = %s", route, conn.writes.String())
		}
	}
	want := []string{
		"/v1/images/models",
		"/v1/images/models/google/gemini-3.1-flash-image/endpoints",
	}
	if fmt.Sprint(paths) != fmt.Sprint(want) {
		t.Fatalf("control-plane paths = %#v, want %#v", paths, want)
	}
}

func TestServeOneModelsOnlyAllowsAnonymousGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"trustedrouter/auto"}]}`)
	}))
	defer server.Close()
	gateway := trustedrouter.New(server.URL, "internal", server.Client())

	request := "POST /v1/models HTTP/1.1\r\nHost: api.trustedrouter.com\r\nContent-Length: 2\r\n\r\n{}"
	conn := newScriptedConn(request, nil)
	serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)
	if !strings.Contains(conn.writes.String(), "HTTP/1.1 401 Unauthorized") {
		t.Fatalf("response = %s", conn.writes.String())
	}
}

func TestServeOnePublicModelsHidesControlPlaneFailureBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "private upstream detail", http.StatusInternalServerError)
	}))
	defer server.Close()

	conn := newScriptedConn("GET /v1/models HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n", nil)
	gateway := trustedrouter.New(server.URL, "internal", server.Client())
	serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)

	out := conn.writes.String()
	if !strings.Contains(out, fmt.Sprintf("HTTP/1.1 %d", http.StatusServiceUnavailable)) {
		t.Fatalf("response = %s", out)
	}
	if strings.Contains(out, "private upstream detail") {
		t.Fatalf("control-plane response leaked: %s", out)
	}
}

// catalogServer answers like the control plane after quill-router#1732: the
// default list is slim, ?include=endpoints restores per-route detail, and the
// per-model endpoints route is anonymous. It records every request target.
func catalogServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var targets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		targets = append(targets, r.URL.RequestURI())
		mu.Unlock()
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-TrustedRouter-Internal-Token") != "" {
			t.Errorf("public catalog received credentials: %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/models" && r.URL.RawQuery == "include=endpoints":
			_, _ = io.WriteString(w, `{"data":[`+
				`{"id":"text-only","architecture":{"output_modalities":["text"]},"trustedrouter":{"endpoints":[{"provider":"full-detail"}]}},`+
				`{"id":"image-only","architecture":{"output_modalities":["image"]},"trustedrouter":{"endpoints":[{"provider":"full-detail"}]}}]}`)
		case r.URL.Path == "/v1/models" && r.URL.RawQuery == "":
			_, _ = io.WriteString(w, `{"data":[`+
				`{"id":"text-only","architecture":{"output_modalities":["text"]},"trustedrouter":{}},`+
				`{"id":"image-only","architecture":{"output_modalities":["image"]},"trustedrouter":{}}]}`)
		case r.URL.Path == "/v1/models/openai/gpt-4o/endpoints" && r.URL.RawQuery == "":
			_, _ = io.WriteString(w, `{"data":[{"endpoint_id":"openai/gpt-4o@openai/prepaid"}]}`)
		default:
			t.Errorf("unexpected control-plane request %s", r.URL.RequestURI())
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, &targets
}

func serveOneRequestText(t *testing.T, gateway *trustedrouter.Client, request string) (*http.Response, []byte) {
	t.Helper()
	conn := newScriptedConn(request, nil)
	serveOne(context.Background(), conn, nil, nil, nil, nil, gateway, nil)
	return readRawHTTPResponse(t, conn.writes.Bytes())
}

func TestServeOnePublicModelsRelaysIncludeEndpoints(t *testing.T) {
	server, targets := catalogServer(t)
	gateway := trustedrouter.New(server.URL, "internal", server.Client())

	for _, tc := range []struct {
		query    string
		complete bool
	}{
		{"", false},
		{"?include=endpoints", true},
		{"?include=ENDPOINTS", true},
		{"?include=foo,%20Endpoints", true},
		{"?include=foo&include=endpoints", true},
		{"?include=foo", false},
		{"?include=", false},
	} {
		resp, body := serveOneRequestText(t, gateway, "GET /v1/models"+tc.query+" HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%q status = %d body=%s", tc.query, resp.StatusCode, body)
		}
		if got := strings.Contains(string(body), "full-detail"); got != tc.complete {
			t.Errorf("%q complete=%v, want %v: %s", tc.query, got, tc.complete, body)
		}
	}
	// One fetch per cached copy, and the include query reaches the control
	// plane in its canonical form only.
	want := []string{"/v1/models", "/v1/models?include=endpoints"}
	if fmt.Sprint(*targets) != fmt.Sprint(want) {
		t.Fatalf("control-plane requests = %v, want %v", *targets, want)
	}
}

func TestServeOnePublicModelsIncludeEndpointsComposesWithOutputModalities(t *testing.T) {
	server, _ := catalogServer(t)
	gateway := trustedrouter.New(server.URL, "internal", server.Client())

	_, body := serveOneRequestText(t, gateway, "GET /v1/models?include=endpoints&output_modalities=image HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n")
	if !strings.Contains(string(body), "image-only") || strings.Contains(string(body), "text-only") || !strings.Contains(string(body), "full-detail") {
		t.Fatalf("filtered complete catalog = %s", body)
	}
}

func TestServeOnePublicModelEndpointsIsAnonymous(t *testing.T) {
	server, targets := catalogServer(t)
	gateway := trustedrouter.New(server.URL, "internal", server.Client())

	// A browser or SDK may send its key anyway; the route must neither need it
	// nor forward it.
	for _, auth := range []string{"", "Authorization: Bearer sk-tr-v1-not-checked\r\n"} {
		resp, body := serveOneRequestText(t, gateway, "GET /v1/models/openai/gpt-4o/endpoints?provider[only]=x HTTP/1.1\r\nHost: api.trustedrouter.com\r\n"+auth+"\r\n")
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "openai/gpt-4o@openai/prepaid") {
			t.Fatalf("status = %d body = %s", resp.StatusCode, body)
		}
		for name, want := range map[string]string{
			"Content-Type":                "application/json",
			"Cache-Control":               "public, max-age=60, stale-if-error=300",
			"Access-Control-Allow-Origin": "*",
			"Vary":                        "Accept-Encoding",
		} {
			if got := resp.Header.Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
	}
	// Query parameters are not relayed (no free-form request to the control
	// plane), and the second request was served from the cache.
	if want := []string{"/v1/models/openai/gpt-4o/endpoints"}; fmt.Sprint(*targets) != fmt.Sprint(want) {
		t.Fatalf("control-plane requests = %v, want %v", *targets, want)
	}
}

func TestServeOnePublicModelEndpointsLeavesOtherShapesBehindAuth(t *testing.T) {
	server, targets := catalogServer(t)
	gateway := trustedrouter.New(server.URL, "internal", server.Client())

	for _, route := range []string{
		"/v1/models/openai/gpt-4o/extra/endpoints",
		"/v1/models/openai/endpoints",
		"/v1/models/openai/gpt-4o/endpoint",
		"/v1/models/../gpt-4o/endpoints",
		"/v1/models/openai/%2E%2E/endpoints",
		"/v1/models/openai/gpt%3F/endpoints",
		"/v1/images/models/../x/endpoints",
	} {
		resp, body := serveOneRequestText(t, gateway, "GET "+route+" HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s status = %d body = %s, want the unchanged 401", route, resp.StatusCode, body)
		}
	}
	if len(*targets) != 0 {
		t.Fatalf("invalid shapes reached the control plane: %v", *targets)
	}
}

func TestServeOnePublicCatalogNegotiatesGzip(t *testing.T) {
	server, _ := catalogServer(t)
	gateway := trustedrouter.New(server.URL, "internal", server.Client())

	for _, route := range []string{
		"/v1/models",
		"/v1/models?include=endpoints",
		"/v1/models/openai/gpt-4o/endpoints",
	} {
		_, identity := serveOneRequestText(t, gateway, "GET "+route+" HTTP/1.1\r\nHost: api.trustedrouter.com\r\n\r\n")
		for _, tc := range []struct {
			acceptEncoding string
			gzip           bool
		}{
			{"", false},
			{"Accept-Encoding: gzip\r\n", true},
			{"Accept-Encoding: br, gzip;q=0.5\r\n", true},
			{"Accept-Encoding: deflate\r\nAccept-Encoding: GZIP\r\n", true},
			{"Accept-Encoding: *\r\n", true},
			{"Accept-Encoding: gzip;q=0\r\n", false},
			{"Accept-Encoding: gzip;q=0, *\r\n", false},
			{"Accept-Encoding: identity\r\n", false},
			{"Accept-Encoding: br\r\n", false},
		} {
			resp, body := serveOneRequestText(t, gateway, "GET "+route+" HTTP/1.1\r\nHost: api.trustedrouter.com\r\n"+tc.acceptEncoding+"\r\n")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s %q status = %d", route, tc.acceptEncoding, resp.StatusCode)
			}
			if got := resp.Header.Get("Vary"); got != "Accept-Encoding" {
				t.Errorf("%s %q Vary = %q", route, tc.acceptEncoding, got)
			}
			if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
				t.Errorf("%s %q Content-Length = %s, body has %d bytes", route, tc.acceptEncoding, got, len(body))
			}
			encoding := resp.Header.Get("Content-Encoding")
			if !tc.gzip {
				if encoding != "" || !bytes.Equal(body, identity) {
					t.Errorf("%s %q encoding = %q, body = %s; want identity", route, tc.acceptEncoding, encoding, body)
				}
				continue
			}
			if encoding != "gzip" {
				t.Fatalf("%s %q Content-Encoding = %q, want gzip", route, tc.acceptEncoding, encoding)
			}
			reader, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				t.Fatalf("%s %q gzip header: %v", route, tc.acceptEncoding, err)
			}
			decoded, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(decoded, identity) {
				t.Fatalf("%s %q decoded = %s, %v; want %s", route, tc.acceptEncoding, decoded, err, identity)
			}
		}
	}
}

func TestAcceptsGzip(t *testing.T) {
	for header, want := range map[string]bool{
		"":                       false,
		"gzip":                   true,
		"GZip":                   true,
		"x-gzip":                 true,
		"gzip, deflate, br":      true,
		"br;q=1.0, gzip;q=0.8":   true,
		"gzip;q=0":               false,
		"gzip; q=0.000":          false,
		"gzip;q=0.001":           true,
		"gzip;q=bogus":           false,
		"gzip;q=2":               false,
		"*":                      true,
		"*;q=0":                  false,
		"*, gzip;q=0":            false,
		"gzip;q=0, x-gzip":       true,
		"identity":               false,
		"deflate, br, zstd":      false,
		"gzipped":                false,
		"gzip;level=9":           true,
		" , ,gzip":               true,
		"identity;q=0, gzip;q=1": true,
	} {
		if got := acceptsGzip(header); got != want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", header, got, want)
		}
	}
}

func TestGzipPublicBodyMemoizesLargeBodies(t *testing.T) {
	large := bytes.Repeat([]byte(`{"id":"m"},`), publicGzipMemoMinBytes/10+1)
	first, err := gzipPublicBody(large)
	if err != nil {
		t.Fatal(err)
	}
	second, err := gzipPublicBody(append([]byte(nil), large...))
	if err != nil {
		t.Fatal(err)
	}
	if &first[0] != &second[0] {
		t.Fatal("an identical large body was compressed twice")
	}
	small := []byte(`{"data":[]}`)
	a, _ := gzipPublicBody(small)
	b, _ := gzipPublicBody(small)
	if &a[0] == &b[0] {
		t.Fatal("a small body was memoized")
	}
	// The memo is bounded: after enough distinct large bodies the first one
	// has been evicted and is compressed again.
	for i := range publicGzipMemoEntries {
		distinct := append([]byte(fmt.Sprintf("%d", i)), large...)
		if _, err := gzipPublicBody(distinct); err != nil {
			t.Fatal(err)
		}
	}
	publicGzipMemo.Lock()
	entries := len(publicGzipMemo.entries)
	publicGzipMemo.Unlock()
	if entries > publicGzipMemoEntries {
		t.Fatalf("memo holds %d entries, cap %d", entries, publicGzipMemoEntries)
	}
	third, err := gzipPublicBody(large)
	if err != nil {
		t.Fatal(err)
	}
	if &third[0] == &first[0] {
		t.Fatal("the memo was not bounded")
	}
}
