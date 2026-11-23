package websearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// Parallel Basic includes up to ten results in one $0.005 search unit.
const ParallelBasicMicrodollars = 5_000

type ParallelClient struct {
	key  string
	http *http.Client
}

func NewParallelClient(key string, transport *http.Client) (*ParallelClient, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, errors.New("web search is not configured")
	}
	client := http.Client{Timeout: 15 * time.Second}
	if transport != nil {
		client = *transport
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ParallelClient{key: key, http: &client}, nil
}

func (c *ParallelClient) Search(ctx context.Context, query string, opts SearchOptions) (Result, error) {
	query = strings.TrimSpace(query)
	if query == "" || !utf8.ValidString(query) || utf8.RuneCountInString(query) > 200 {
		return Result{}, errors.New("parallel search requires a query of 1 to 200 characters")
	}
	if opts.SearchType != "" && opts.SearchType != "auto" {
		return Result{}, errors.New("parallel search supports mode auto only")
	}
	count := opts.NumResults
	if count == 0 {
		count = defaultNumResults
	}
	if count < 1 || count > 10 {
		return Result{}, errors.New("parallel search supports 1 to 10 results")
	}
	settings := map[string]any{"max_results": count}
	perResult := opts.MaxCharacters
	if perResult < 1 {
		perResult = 4000
	}
	perResult = min(perResult, MaxSnippetBytes)
	policy := map[string][]string{}
	if len(opts.IncludeDomains) > 0 {
		policy["include_domains"] = opts.IncludeDomains
	}
	if len(opts.ExcludeDomains) > 0 {
		policy["exclude_domains"] = opts.ExcludeDomains
	}
	if len(policy) > 0 {
		settings["source_policy"] = policy
	}
	if opts.UserLocation != "" {
		settings["location"] = strings.ToLower(opts.UserLocation)
	}
	body, err := json.Marshal(map[string]any{"search_queries": []string{query}, "mode": "basic", "advanced_settings": settings, "max_chars_total": min(10000, count*perResult)})
	if err != nil {
		return Result{}, errors.New("could not encode web search request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.parallel.ai/v1/search", bytes.NewReader(body))
	if err != nil {
		return Result{}, errors.New("could not create web search request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.key)
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, errors.New("web search provider unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, &ProviderError{StatusCode: resp.StatusCode, Retryable: resp.StatusCode == 429 || resp.StatusCode >= 500}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return Result{}, errors.New("invalid web search response size")
	}
	var data struct {
		ID    string `json:"search_id"`
		Usage []struct {
			Name  string
			Count int
		}
		Results []struct {
			Title, URL string
			Date       string `json:"publish_date"`
			Excerpts   []string
		}
		Warnings []json.RawMessage
	}
	if json.Unmarshal(raw, &data) != nil || strings.TrimSpace(data.ID) == "" || data.Results == nil || len(data.Results) > count || len(data.Warnings) > 0 {
		return Result{}, errors.New("invalid or degraded parallel search response")
	}
	if len(data.Usage) != 1 || data.Usage[0].Name != "sku_search" || data.Usage[0].Count != 1 {
		return Result{}, errors.New("unexpected parallel search usage")
	}
	rows := make([]exaResult, 0, len(data.Results))
	for _, r := range data.Results {
		rows = append(rows, exaResult{Title: r.Title, URL: r.URL, PublishedDate: r.Date, Text: truncateUTF8(strings.Join(r.Excerpts, "\n"), perResult)})
	}
	return Result{RequestID: truncateUTF8(data.ID, 256), Sources: sanitizeSources(rows, count), CostMicrodollars: ParallelBasicMicrodollars}, nil
}
