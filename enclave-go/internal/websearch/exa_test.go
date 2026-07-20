package websearch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestExaClientLive(t *testing.T) {
	if os.Getenv("TR_TEST_EXA_LIVE") != "1" {
		t.Skip("set TR_TEST_EXA_LIVE=1 for the opt-in provider smoke")
	}
	client, err := NewExaClient(ExaOptions{APIKey: os.Getenv("EXA_API_KEY")})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Search(context.Background(), "TrustedRouter official website", SearchOptions{NumResults: 1, SearchType: "instant"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sources) != 1 || result.CostMicrodollars <= 0 {
		t.Fatalf("live result shape = sources:%d cost_microdollars:%d", len(result.Sources), result.CostMicrodollars)
	}
}

func TestExaClientSearchUsesBoundedAuthenticatedRequest(t *testing.T) {
	t.Parallel()

	var requestBody map[string]any
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("x-api-key"); got != "exa-secret" {
			t.Fatalf("x-api-key = %q", got)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/search" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		return testResponse(http.StatusOK, `{
			"requestId":"exa_req_1",
			"costDollars":{"total":0.007001},
			"results":[{
				"title":"Official result",
				"url":"https://example.com/current",
				"publishedDate":"2026-07-19T00:00:00Z",
				"author":"Example",
				"highlights":["The current fact."]
			}]
		}`), nil
	})}

	client, err := NewExaClient(ExaOptions{
		APIKey:     "exa-secret",
		Endpoint:   "https://example.test/search",
		HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatalf("NewExaClient: %v", err)
	}
	result, err := client.Search(context.Background(), "current fact", SearchOptions{
		NumResults:     5,
		SearchType:     "fast",
		IncludeDomains: []string{"example.com"},
		ExcludeDomains: []string{"spam.example"},
		UserLocation:   "US",
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}

	if requestBody["query"] != "current fact" || requestBody["type"] != "fast" || requestBody["numResults"] != float64(5) {
		t.Fatalf("request body = %#v", requestBody)
	}
	if requestBody["userLocation"] != "US" {
		t.Fatalf("userLocation = %#v", requestBody["userLocation"])
	}
	contents, ok := requestBody["contents"].(map[string]any)
	if !ok || contents["highlights"] != true {
		t.Fatalf("contents = %#v", requestBody["contents"])
	}
	if result.RequestID != "exa_req_1" || result.CostMicrodollars != 7001 || len(result.Sources) != 1 {
		t.Fatalf("result = %#v", result)
	}
	if result.Sources[0].Snippet != "The current fact." {
		t.Fatalf("snippet = %q", result.Sources[0].Snippet)
	}
}

func TestExaClientRejectsMissingKeyAndOversizedQuery(t *testing.T) {
	t.Parallel()

	if _, err := NewExaClient(ExaOptions{}); err == nil {
		t.Fatal("expected missing API key error")
	}
	client, err := NewExaClient(ExaOptions{APIKey: "secret"})
	if err != nil {
		t.Fatalf("NewExaClient: %v", err)
	}
	if _, err := client.Search(context.Background(), strings.Repeat("q", MaxQueryBytes+1), SearchOptions{}); err == nil {
		t.Fatal("expected oversized query error")
	}
}

func TestExaClientClassifiesProviderErrorsWithoutLeakingBodies(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusTooManyRequests, `{"error":"query and secret material must not escape"}`), nil
	})}
	client, err := NewExaClient(ExaOptions{APIKey: "secret", Endpoint: "https://example.test/search", HTTPClient: httpClient})
	if err != nil {
		t.Fatalf("NewExaClient: %v", err)
	}
	_, err = client.Search(context.Background(), "private query", SearchOptions{})
	if err == nil {
		t.Fatal("expected provider error")
	}
	providerErr, ok := err.(*ProviderError)
	if !ok || providerErr.StatusCode != http.StatusTooManyRequests || !providerErr.Retryable {
		t.Fatalf("error = %#v", err)
	}
	encoded := err.Error()
	for _, forbidden := range []string{"private query", "secret material", "secret"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("error leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestExaClientBoundsResponseAndSanitizesSources(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, `{"requestId":"r","costDollars":{"total":0.0000005},"results":[`+
			`{"title":"`+strings.Repeat("T", MaxTitleBytes+20)+`","url":"javascript:alert(1)","text":"bad"},`+
			`{"title":"Good","url":"https://example.com","text":"`+strings.Repeat("x", MaxSnippetBytes+20)+`"}`+
			`]}`), nil
	})}
	client, err := NewExaClient(ExaOptions{APIKey: "secret", Endpoint: "https://example.test/search", HTTPClient: httpClient})
	if err != nil {
		t.Fatalf("NewExaClient: %v", err)
	}
	result, err := client.Search(context.Background(), "query", SearchOptions{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.CostMicrodollars != 1 {
		t.Fatalf("rounded microdollars = %d", result.CostMicrodollars)
	}
	if len(result.Sources) != 1 || len(result.Sources[0].Snippet) != MaxSnippetBytes {
		t.Fatalf("sources = %#v", result.Sources)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func testResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
