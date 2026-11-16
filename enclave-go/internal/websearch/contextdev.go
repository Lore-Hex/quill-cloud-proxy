package websearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ContextCreditMicrodollars is an operator-approved conservative tariff, not
// measured upstream dollar cost: twice the published $0.003/credit top-up rate.
const ContextCreditMicrodollars = 6_000

type ContextOptions struct {
	APIKey     string
	Endpoint   string
	HTTPClient *http.Client
}

type ContextClient struct {
	apiKey   string
	endpoint string
	http     *http.Client
}

func NewContextClient(options ContextOptions) (*ContextClient, error) {
	key := strings.TrimSpace(options.APIKey)
	if key == "" {
		return nil, errors.New("web search is not configured")
	}
	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = "https://api.context.dev/v1/web/search"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !isLocalTestEndpoint(u)) {
		return nil, errors.New("web search endpoint is invalid")
	}
	client := http.Client{Timeout: 15 * time.Second}
	if options.HTTPClient != nil {
		client = *options.HTTPClient
	}
	// Never forward the managed credential to a redirect destination.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ContextClient{apiKey: key, endpoint: endpoint, http: &client}, nil
}

func ContextMaxCredits(results int) int {
	if results < 1 {
		results = defaultNumResults
	}
	return 2 * ((min(results, maxNumResults) + 9) / 10)
}

func (c *ContextClient) Search(ctx context.Context, query string, options SearchOptions) (Result, error) {
	query = strings.TrimSpace(query)
	if query == "" || !utf8.ValidString(query) || utf8.RuneCountInString(query) > 500 {
		return Result{}, errors.New("context.dev search query must contain 1 to 500 characters")
	}
	if options.SearchType != "" && options.SearchType != "auto" {
		return Result{}, errors.New("context.dev does not support Exa search modes")
	}
	count := options.NumResults
	if count < 1 {
		count = defaultNumResults
	}
	count = min(count, maxNumResults)
	characters := options.MaxCharacters
	if characters < 1 {
		characters = 4000
	}
	characters = max(100, min(characters, 20_000))
	payload := map[string]any{
		"query": query, "numResults": count,
		"highlightsOptions": map[string]any{"enabled": true, "maxCharacters": characters},
		"timeoutOpts":       map[string]any{"milliseconds": 10_000, "behavior": "return-partial"},
	}
	if len(options.IncludeDomains) > 0 {
		payload["includeDomains"] = options.IncludeDomains
	}
	if len(options.ExcludeDomains) > 0 {
		payload["excludeDomains"] = options.ExcludeDomains
	}
	if options.UserLocation != "" {
		payload["country"] = strings.ToLower(options.UserLocation)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Result{}, errors.New("could not encode web search request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{}, errors.New("could not create web search request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, errors.New("web search provider unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32<<10))
		return Result{}, &ProviderError{StatusCode: resp.StatusCode, Retryable: resp.StatusCode == 429 || resp.StatusCode >= 500}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return Result{}, errors.New("invalid web search response size")
	}
	var decoded struct {
		RequestID   string `json:"request_id"`
		KeyMetadata struct {
			Credits *int `json:"credits_consumed"`
		} `json:"key_metadata"`
		Results []struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Description string `json:"description"`
			Highlights  struct {
				Code string   `json:"code"`
				Text []string `json:"highlights"`
			} `json:"highlights"`
		} `json:"results"`
	}
	if json.Unmarshal(raw, &decoded) != nil {
		return Result{}, errors.New("web search provider returned invalid JSON")
	}
	if decoded.KeyMetadata.Credits == nil || decoded.Results == nil || strings.TrimSpace(decoded.RequestID) == "" {
		return Result{}, errors.New("web search provider returned incomplete metadata")
	}
	credits := *decoded.KeyMetadata.Credits
	if credits < 0 || credits > ContextMaxCredits(count) {
		return Result{}, errors.New("web search provider returned invalid credit usage")
	}
	if header := resp.Header.Get("X-Credits-Used"); header != "" {
		h, err := strconv.ParseInt(header, 10, 64)
		if err != nil || h != int64(credits) {
			return Result{}, errors.New("web search provider credit usage disagrees")
		}
	}
	if len(decoded.Results) > count {
		return Result{}, errors.New("web search provider exceeded result limit")
	}
	sources := make([]exaResult, 0, len(decoded.Results))
	for _, row := range decoded.Results {
		item := exaResult{Title: row.Title, URL: row.URL, Text: row.Description}
		if row.Highlights.Code == "SUCCESS" {
			item.Highlights = row.Highlights.Text
		}
		sources = append(sources, item)
	}
	return Result{
		RequestID:        truncateUTF8(strings.TrimSpace(decoded.RequestID), 256),
		Sources:          sanitizeSources(sources, count),
		CostMicrodollars: int(credits) * ContextCreditMicrodollars,
	}, nil
}
