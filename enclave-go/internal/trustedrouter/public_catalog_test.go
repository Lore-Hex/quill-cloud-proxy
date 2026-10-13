package trustedrouter

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func assertAnonymousCatalogRequest(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Method != http.MethodGet {
		t.Errorf("method = %s, want GET", r.Method)
	}
	if got := r.Header.Get("Authorization"); got != "" {
		t.Errorf("authorization leaked to public catalog: %q", got)
	}
	if got := r.Header.Get(internalTokenHeader); got != "" {
		t.Errorf("internal token leaked to public catalog: %q", got)
	}
}

func TestPublicModelsWithEndpointsIsASeparateCachedCopy(t *testing.T) {
	var defaultCalls, fullCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAnonymousCatalogRequest(t, r)
		if r.URL.Path != "/v1/models" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.RawQuery {
		case "":
			defaultCalls.Add(1)
			_, _ = io.WriteString(w, `{"data":[{"id":"m","trustedrouter":{}}]}`)
		case "include=endpoints":
			fullCalls.Add(1)
			_, _ = io.WriteString(w, `{"data":[{"id":"m","trustedrouter":{"endpoints":[{"provider":"p"}]}}]}`)
		default:
			t.Errorf("unexpected query %q", r.URL.RawQuery)
			http.Error(w, "bad query", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := New(server.URL, "internal-secret", server.Client())

	for range 2 {
		full, err := client.PublicModelsWithEndpoints(t.Context())
		if err != nil {
			t.Fatalf("PublicModelsWithEndpoints: %v", err)
		}
		if !strings.Contains(string(full), `"endpoints"`) {
			t.Fatalf("complete catalog = %s", full)
		}
		full[0] = 'x' // callers own their copy
		slim, err := client.PublicModels(t.Context())
		if err != nil {
			t.Fatalf("PublicModels: %v", err)
		}
		if strings.Contains(string(slim), `"endpoints"`) {
			t.Fatalf("default catalog served the complete copy: %s", slim)
		}
	}
	if defaultCalls.Load() != 1 || fullCalls.Load() != 1 {
		t.Fatalf("control-plane calls default=%d full=%d, want one each (both cached)", defaultCalls.Load(), fullCalls.Load())
	}
}

func TestPublicModelsWithEndpointsUsesBoundedStaleCopyOnRefreshFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"data":[{"id":"m","trustedrouter":{"endpoints":[]}}]}`)
			return
		}
		http.Error(w, "temporary failure", http.StatusBadGateway)
	}))
	defer server.Close()
	client := New(server.URL, "internal", server.Client())

	want, err := client.PublicModelsWithEndpoints(t.Context())
	if err != nil {
		t.Fatalf("prime: %v", err)
	}
	client.fullModelsFetched = time.Now().Add(-publicModelsFreshTTL - time.Second)
	got, err := client.PublicModelsWithEndpoints(t.Context())
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("stale fallback = %s, %v; want %s", got, err, want)
	}
	client.fullModelsFetched = time.Now().Add(-publicModelsStaleTTL - time.Second)
	if _, err := client.PublicModelsWithEndpoints(t.Context()); err == nil {
		t.Fatal("a copy older than the stale TTL was served")
	}
	if calls.Load() != 3 {
		t.Fatalf("control-plane calls = %d, want 3", calls.Load())
	}
}

func TestPublicModelsWithEndpointsKeepsTheSizeCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"`+strings.Repeat("x", publicModelsMaxBytes)+`"}]}`)
	}))
	defer server.Close()
	client := New(server.URL, "internal", server.Client())
	if _, err := client.PublicModelsWithEndpoints(t.Context()); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized complete catalog error = %v", err)
	}
}

func TestPublicModelEndpointsRelaysAnonymouslyAndCaches(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assertAnonymousCatalogRequest(t, r)
		if r.URL.RawQuery != "" {
			t.Errorf("query forwarded: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/models/openai/gpt-4o:free/endpoints":
			_, _ = io.WriteString(w, `{"data":[{"endpoint_id":"openai/gpt-4o@openai/prepaid"}]}`)
		case "/v1/models/nobody/nothing/endpoints":
			// The control plane answers an unknown model with an empty list.
			_, _ = io.WriteString(w, `{"data":[]}`)
		default:
			t.Errorf("path = %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL, "internal-secret", server.Client())

	for range 2 {
		body, err := client.PublicModelEndpoints(t.Context(), "openai/gpt-4o:free")
		if err != nil || !strings.Contains(string(body), "openai/gpt-4o@openai/prepaid") {
			t.Fatalf("PublicModelEndpoints = %s, %v", body, err)
		}
		body[0] = 'x' // callers own their copy
	}
	if calls.Load() != 1 {
		t.Fatalf("control-plane calls = %d, want 1 (second read cached)", calls.Load())
	}
	empty, err := client.PublicModelEndpoints(t.Context(), "nobody/nothing")
	if err != nil || string(empty) != `{"data":[]}` {
		t.Fatalf("unknown model = %s, %v; want the control plane's empty list", empty, err)
	}
}

func TestPublicModelEndpointsRejectsMalformedManifests(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
	}{
		{"null data", "application/json", `{"data":null}`},
		{"missing data", "application/json", `{"endpoints":[]}`},
		{"object data", "application/json", `{"data":{}}`},
		{"not json", "application/json", `nope`},
		{"html page", "text/html; charset=utf-8", `<html>{"data":[]}</html>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := New(server.URL, "internal", server.Client())
			if body, err := client.PublicModelEndpoints(t.Context(), "openai/gpt-4o"); err == nil {
				t.Fatalf("accepted %s", body)
			}
			if len(client.modelEndpoints) != 0 {
				t.Fatalf("a rejected manifest was cached: %v", client.modelEndpoints)
			}
		})
	}
}

func TestPublicModelEndpointsRejectsInvalidIDsWithoutFetching(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer server.Close()
	client := New(server.URL, "internal", server.Client())

	for _, modelID := range []string{
		"", "openai", "openai/", "/gpt-4o", "a/b/c",
		"../x", "./x", "a/..", "a/.", "../..",
		"a/b?x=1", "a/b#frag", "a/b%2e", "a b/c", "a/b\nc",
		"openai/" + strings.Repeat("x", publicModelIDMaxBytes),
	} {
		if _, err := client.PublicModelEndpoints(t.Context(), modelID); err == nil {
			t.Errorf("model id %q was accepted", modelID)
		}
		if _, err := client.PublicImageModelEndpoints(t.Context(), modelID); err == nil {
			t.Errorf("image model id %q was accepted", modelID)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid IDs reached the control plane %d times", calls.Load())
	}
	for _, modelID := range []string{"openai/gpt-4o", "z-ai/glm-5.3", "meta-llama/llama-3.1-8b-instruct:free", "a.b/c..d"} {
		if !ValidPublicModelID(modelID) {
			t.Errorf("real-shaped model id %q was refused", modelID)
		}
	}
}

func TestPublicModelEndpointsUsesBoundedStaleCopyOnRefreshFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"data":[{"endpoint_id":"e"}]}`)
			return
		}
		http.Error(w, "temporary failure", http.StatusBadGateway)
	}))
	defer server.Close()
	client := New(server.URL, "internal", server.Client())

	want, err := client.PublicModelEndpoints(t.Context(), "a/b")
	if err != nil {
		t.Fatalf("prime: %v", err)
	}
	age := func(d time.Duration) {
		client.modelEndpointsMu.Lock()
		entry := client.modelEndpoints["a/b"]
		entry.fetched = time.Now().Add(-d)
		client.modelEndpoints["a/b"] = entry
		client.modelEndpointsMu.Unlock()
	}
	age(publicModelsFreshTTL + time.Second)
	if got, err := client.PublicModelEndpoints(t.Context(), "a/b"); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("stale fallback = %s, %v; want %s", got, err, want)
	}
	age(publicModelsStaleTTL + time.Second)
	if _, err := client.PublicModelEndpoints(t.Context(), "a/b"); err == nil {
		t.Fatal("a manifest older than the stale TTL was served")
	}
}

func TestPublicModelEndpointsCacheIsBoundedByCountAndBytes(t *testing.T) {
	client := New("http://127.0.0.1:1", "internal", nil)
	base := time.Now()
	checkAccounting := func() {
		t.Helper()
		total := 0
		for id, entry := range client.modelEndpoints {
			total += publicModelEndpointsCost(id, entry.body)
		}
		if total != client.modelEndpointsBytes {
			t.Fatalf("byte accounting = %d, entries sum to %d", client.modelEndpointsBytes, total)
		}
		if len(client.modelEndpoints) > publicModelEndpointsCacheEntries || client.modelEndpointsBytes > publicModelEndpointsCacheBytes {
			t.Fatalf("cache over budget: %d entries, %d bytes", len(client.modelEndpoints), client.modelEndpointsBytes)
		}
	}

	// Count bound: tiny manifests for many caller-chosen IDs.
	for i := range publicModelEndpointsCacheEntries + 10 {
		client.storePublicModelEndpoints(fmt.Sprintf("a/m%d", i), []byte(`{"data":[]}`), base.Add(time.Duration(i)))
	}
	checkAccounting()
	if len(client.modelEndpoints) != publicModelEndpointsCacheEntries {
		t.Fatalf("entries = %d, want %d", len(client.modelEndpoints), publicModelEndpointsCacheEntries)
	}
	if _, ok := client.modelEndpoints["a/m0"]; ok {
		t.Fatal("the oldest entry survived eviction")
	}
	if _, ok := client.modelEndpoints[fmt.Sprintf("a/m%d", publicModelEndpointsCacheEntries+9)]; !ok {
		t.Fatal("the newest entry was not retained")
	}

	// Byte bound: large manifests evict older entries.
	big := bytes.Repeat([]byte("x"), publicModelEndpointsEntryMaxBytes)
	for i := range 20 {
		client.storePublicModelEndpoints(fmt.Sprintf("b/m%d", i), big, base.Add(time.Hour+time.Duration(i)))
		checkAccounting()
	}
	if _, ok := client.modelEndpoints["b/m19"]; !ok {
		t.Fatal("the newest large entry was not retained")
	}

	// Replacing an entry does not double-count it.
	client.storePublicModelEndpoints("b/m19", []byte(`{"data":[]}`), base.Add(2*time.Hour))
	checkAccounting()

	// An oversized manifest is never retained.
	client.storePublicModelEndpoints("c/huge", append(big, 'x'), base.Add(3*time.Hour))
	if _, ok := client.modelEndpoints["c/huge"]; ok {
		t.Fatal("an oversized manifest was cached")
	}
	checkAccounting()
}
