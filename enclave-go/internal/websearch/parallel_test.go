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

func TestParallelLiveSearch(t *testing.T) {
	if os.Getenv("TR_RUN_PARALLEL_LIVE") != "1" {
		t.Skip("opt-in single billable search")
	}
	c, err := NewParallelClient(os.Getenv("PARALLEL_API_KEY"), nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Search(t.Context(), "Parallel API documentation", SearchOptions{NumResults: 1, MaxCharacters: 15000})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequestID == "" || len(result.Sources) != 1 || result.CostMicrodollars != ParallelBasicMicrodollars {
		t.Fatal("unexpected search result count or charge")
	}
}

func TestParallelBasicContract(t *testing.T) {
	for _, tc := range []struct {
		name, usage string
		ok          bool
	}{
		{"metered", `[{"name":"sku_search","count":1}]`, true},
		{"missing", "null", false},
		{"unknown", `[{"name":"sku_extract","count":1}]`, false},
		{"unexpected quantity", `[{"name":"sku_search","count":2}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewParallelClient("test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://api.parallel.ai/v1/search" || r.Method != "POST" || r.Header.Get("x-api-key") != "test" {
					t.Fatal("incorrect request destination or auth")
				}
				var body struct {
					Mode     string
					Chars    int      `json:"max_chars_total"`
					Queries  []string `json:"search_queries"`
					Settings struct {
						Count      int                 `json:"max_results"`
						Deprecated json.RawMessage     `json:"excerpt_settings"`
						Policy     map[string][]string `json:"source_policy"`
					} `json:"advanced_settings"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil || body.Mode != "basic" || body.Chars != 8 || body.Settings.Deprecated != nil || len(body.Queries) != 1 || body.Queries[0] != "docs" || body.Settings.Count != 2 || len(body.Settings.Policy["include_domains"]) != 1 {
					t.Fatal("incorrect provider payload")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"search_id":"s","usage":` + tc.usage + `,"results":[{"url":"https://example.com","excerpts":["excerpt"]}]}`))}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			result, err := c.Search(context.Background(), "docs", SearchOptions{NumResults: 2, MaxCharacters: 4, IncludeDomains: []string{"example.com"}})
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected success=%t", err == nil)
			}
			if tc.ok && (result.CostMicrodollars != 5000 || len(result.Sources) != 1 || result.Sources[0].Snippet != "exce") {
				t.Fatal("incorrect result or tariff")
			}
		})
	}
}

func TestParallelRefusesRedirectAndInvalidInputs(t *testing.T) {
	var calls int
	c, err := NewParallelClient("test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls > 1 {
			t.Fatal("forwarded managed key on redirect")
		}
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": {"https://other.example/search"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []SearchOptions{{NumResults: 11}, {SearchType: "deep"}} {
		if _, err := c.Search(context.Background(), "test", opts); err == nil {
			t.Fatal("accepted unsupported options")
		}
	}
	if calls != 0 {
		t.Fatal("dispatched invalid input")
	}
	if _, err := c.Search(context.Background(), "test", SearchOptions{}); err == nil || calls != 1 {
		t.Fatal("expected a single refused redirect")
	}
	if _, err := NewParallelClient(" ", nil); err == nil {
		t.Fatal("configured without a key")
	}
}
