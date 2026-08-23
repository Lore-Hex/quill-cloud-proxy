package trustedrouter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The live GCP failure, in one table.
//
// TR_CONTROL_PLANE_BASE_URL is NOT versioned — the internal endpoints are
// absolute from the domain root — so GCP ships https://trustedrouter.com and
// that is right for every other caller. PublicModels alone assumed /v1 was
// already there and fetched /models, the human-facing HTML page, which answers
// 200 with text/html.
func TestPublicModelsURLIsVersionedWhicheverBaseIsGiven(t *testing.T) {
	for _, tc := range []struct{ base, want string }{
		// What GCP actually ships. Produced .../models before this fix.
		{"https://trustedrouter.com", "https://trustedrouter.com/v1/models"},
		// Defensive normalization for a legacy versioned value. Configuration
		// validation now rejects this form before the client is constructed.
		{"https://azure.trustedrouter.com/v1", "https://azure.trustedrouter.com/v1/models"},
		// Trailing slashes in either form.
		{"https://trustedrouter.com/", "https://trustedrouter.com/v1/models"},
		{"https://trustedrouter.com/v1/", "https://trustedrouter.com/v1/models"},
		{"  https://trustedrouter.com/v1  ", "https://trustedrouter.com/v1/models"},
	} {
		if got := publicModelsURL(tc.base); got != tc.want {
			t.Errorf("publicModelsURL(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}
}

func TestAnHTMLPageIsRejectedEvenWithA200(t *testing.T) {
	// The exact live failure: 200 OK, text/html, so the status check passes and
	// only the body betrays it. The error must name the content type, or the
	// next person sees "invalid /models response" and looks at the catalog
	// instead of the URL.
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>models</body></html>"))
	}))
	defer srv.Close()

	c := New(srv.URL, "internal", srv.Client())
	_, err := c.PublicModels(context.Background())
	if err == nil {
		t.Fatal("an HTML page was accepted as the model catalog")
	}
	if !strings.Contains(err.Error(), "HTML") || !strings.Contains(err.Error(), "text/html") {
		t.Errorf("error should say it got HTML and name the type, got: %v", err)
	}
	if gotPath != "/v1/models" {
		t.Errorf("fetched %q, want /v1/models", gotPath)
	}
}

func TestTheVersionedPathIsRequestedFromAnUnversionedBase(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"m"}]}`))
	}))
	defer srv.Close()

	// srv.URL has no /v1 — exactly the shape GCP passes.
	c := New(srv.URL, "internal", srv.Client())
	body, err := c.PublicModels(context.Background())
	if err != nil {
		t.Fatalf("PublicModels: %v", err)
	}
	if gotPath != "/v1/models" {
		t.Fatalf("fetched %q, want /v1/models", gotPath)
	}
	if !strings.Contains(string(body), `"m"`) {
		t.Fatalf("unexpected body: %s", body)
	}
}
