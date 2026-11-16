package websearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const contextResponse = `{"request_id":"context-1","key_metadata":{"credits_consumed":2},"results":[{"title":"Python","url":"https://docs.python.org/3/","description":"fallback","highlights":{"code":"SUCCESS","highlights":["Documentation"]}}]}`

func TestContextClientSearchContract(t *testing.T) {
	var sent map[string]any
	calls := 0
	client, err := NewContextClient(ContextOptions{APIKey: "context-secret", HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.context.dev/v1/web/search" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer context-secret" {
			t.Fatal("incorrect provider request")
		}
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Fatal(err)
		}
		resp := testResponse(200, contextResponse)
		resp.Header = http.Header{"X-Credits-Used": []string{"2"}}
		return resp, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Search(context.Background(), "Python docs", SearchOptions{NumResults: 1, SearchType: "auto", MaxCharacters: 30000, IncludeDomains: []string{"docs.python.org"}, ExcludeDomains: []string{"spam.test"}, UserLocation: "US"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || result.CostMicrodollars != 12000 || len(result.Sources) != 1 || result.Sources[0].Snippet != "Documentation" {
		t.Fatalf("result = %+v, calls=%d", result, calls)
	}
	if sent["country"] != "us" || sent["numResults"] != float64(1) || sent["type"] != nil || sent["markdownOptions"] != nil || sent["zdr"] != nil {
		t.Fatalf("unexpected payload: %+v", sent)
	}
	if sent["highlightsOptions"].(map[string]any)["maxCharacters"] != float64(20000) {
		t.Fatal("highlights are not bounded")
	}
	if sent["timeoutOpts"].(map[string]any)["milliseconds"] != float64(10000) {
		t.Fatal("missing provider deadline")
	}
	if len(sent["includeDomains"].([]any)) != 1 || len(sent["excludeDomains"].([]any)) != 1 {
		t.Fatal("lost domain filters")
	}
}

func TestContextRejectsInvalidCreditUsage(t *testing.T) {
	for _, credits := range []string{`null`, `-1`, `3`, `1.5`, `"2"`, `true`, `99999999999999999999`} {
		t.Run(credits, func(t *testing.T) {
			client, _ := NewContextClient(ContextOptions{APIKey: "secret", HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return testResponse(200, strings.Replace(contextResponse, `"credits_consumed":2`, `"credits_consumed":`+credits, 1)), nil
			})}})
			if _, err := client.Search(context.Background(), "q", SearchOptions{NumResults: 1}); err == nil {
				t.Fatal("accepted invalid usage")
			}
		})
	}
	for _, body := range []string{`{}`, `{"request_id":"id","key_metadata":{"credits_consumed":0}}`, contextResponse + `{}`, strings.Repeat("x", maxResponseBytes+1)} {
		client, _ := NewContextClient(ContextOptions{APIKey: "secret", HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return testResponse(200, body), nil })}})
		if _, err := client.Search(context.Background(), "q", SearchOptions{}); err == nil {
			t.Fatal("accepted malformed response")
		}
	}
}

func TestContextErrorsAreRedactedAndNeverRetried(t *testing.T) {
	for _, status := range []int{301, 400, 401, 403, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			client, _ := NewContextClient(ContextOptions{APIKey: "secret", HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return testResponse(status, "private response secret"), nil
			})}})
			_, err := client.Search(context.Background(), "private query", SearchOptions{})
			var providerErr *ProviderError
			if !errors.As(err, &providerErr) || providerErr.StatusCode != status || calls != 1 || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe error %v / calls=%d", err, calls)
			}
		})
	}
}

func TestContextDoesNotFollowRedirects(t *testing.T) {
	hits := 0
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer origin.Close()
	client, _ := NewContextClient(ContextOptions{APIKey: "secret", Endpoint: origin.URL})
	if _, err := client.Search(context.Background(), "q", SearchOptions{}); err == nil || hits != 0 {
		t.Fatal("redirect followed")
	}
}

func TestContextOptionsAndBounds(t *testing.T) {
	if _, err := NewContextClient(ContextOptions{}); err == nil {
		t.Fatal("missing key accepted")
	}
	for _, endpoint := range []string{"http://remote.test", "https://user:pass@remote.test", "file:///etc/passwd"} {
		if _, err := NewContextClient(ContextOptions{APIKey: "key", Endpoint: endpoint}); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
	client, _ := NewContextClient(ContextOptions{APIKey: "secret", HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("invalid input sent"); return nil, nil })}})
	for _, query := range []string{"", strings.Repeat("x", 501)} {
		if _, err := client.Search(context.Background(), query, SearchOptions{}); err == nil {
			t.Fatal("invalid query accepted")
		}
	}
	if _, err := client.Search(context.Background(), "q", SearchOptions{SearchType: "deep"}); err == nil {
		t.Fatal("unsupported mode accepted")
	}
	for results, want := range map[int]int{0: 2, 1: 2, 10: 2, 11: 4, 20: 4, 25: 6, 100: 6} {
		if got := ContextMaxCredits(results); got != want {
			t.Fatalf("credits(%d)=%d want %d", results, got, want)
		}
	}
}

func TestContextChecksHeaderAndSanitizesSources(t *testing.T) {
	for _, header := range []string{"1", "2.0", "invalid"} {
		client, _ := NewContextClient(ContextOptions{APIKey: "secret", HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			resp := testResponse(200, contextResponse)
			resp.Header = http.Header{"X-Credits-Used": []string{header}}
			return resp, nil
		})}})
		if _, err := client.Search(context.Background(), "q", SearchOptions{}); err == nil {
			t.Fatal("inconsistent header accepted")
		}
	}
	client, _ := NewContextClient(ContextOptions{APIKey: "secret", HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testResponse(200, strings.Replace(contextResponse, "https://docs.python.org/3/", "javascript:alert(1)", 1)), nil
	})}})
	result, err := client.Search(context.Background(), "q", SearchOptions{})
	if err != nil || len(result.Sources) != 0 || result.CostMicrodollars != 12000 {
		t.Fatal("invalid sources or changed charge")
	}
}
