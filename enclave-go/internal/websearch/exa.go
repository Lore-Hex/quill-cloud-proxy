// Package websearch provides the enclave-owned hosted web-search transport.
// Queries and result contents stay inside the attested request path; callers
// receive only model-selected citations and source metadata.
package websearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultExaEndpoint = "https://api.exa.ai/search"
	defaultNumResults  = 5
	maxNumResults      = 10
	maxResponseBytes   = 2 << 20
	MaxQueryBytes      = 4096
	MaxTitleBytes      = 512
	MaxSnippetBytes    = 8192
	maxTotalSnippetLen = 48 << 10
)

type ExaOptions struct {
	APIKey     string
	Endpoint   string
	HTTPClient *http.Client
}

type SearchOptions struct {
	NumResults     int
	SearchType     string
	IncludeDomains []string
	ExcludeDomains []string
	UserLocation   string
}

type Source struct {
	Title         string `json:"title"`
	URL           string `json:"url"`
	PublishedDate string `json:"published_date,omitempty"`
	Author        string `json:"author,omitempty"`
	Snippet       string `json:"snippet"`
}

type Result struct {
	RequestID        string   `json:"request_id,omitempty"`
	Sources          []Source `json:"sources"`
	CostMicrodollars int      `json:"cost_microdollars"`
}

type ProviderError struct {
	StatusCode int
	Retryable  bool
}

func (e *ProviderError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("web search provider returned HTTP %d", e.StatusCode)
}

type Client interface {
	Search(context.Context, string, SearchOptions) (Result, error)
}

type ExaClient struct {
	apiKey   string
	endpoint string
	http     *http.Client
}

func NewExaClient(options ExaOptions) (*ExaClient, error) {
	apiKey := strings.TrimSpace(options.APIKey)
	if apiKey == "" {
		return nil, errors.New("web search is not configured")
	}
	endpoint := strings.TrimSpace(options.Endpoint)
	if endpoint == "" {
		endpoint = defaultExaEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !isLocalTestEndpoint(parsed)) {
		return nil, errors.New("web search endpoint is invalid")
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &ExaClient{apiKey: apiKey, endpoint: endpoint, http: httpClient}, nil
}

func isLocalTestEndpoint(parsed *url.URL) bool {
	if parsed == nil || parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func (c *ExaClient) Search(ctx context.Context, query string, options SearchOptions) (Result, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return Result{}, errors.New("web search query is required")
	}
	if len(query) > MaxQueryBytes {
		return Result{}, errors.New("web search query is too large")
	}
	numResults := options.NumResults
	if numResults <= 0 {
		numResults = defaultNumResults
	}
	if numResults > maxNumResults {
		numResults = maxNumResults
	}
	searchType := strings.TrimSpace(options.SearchType)
	if searchType == "" {
		searchType = "fast"
	}
	payload := map[string]any{
		"query":      query,
		"type":       searchType,
		"numResults": numResults,
		"contents": map[string]any{
			"highlights": true,
		},
	}
	if len(options.IncludeDomains) > 0 {
		payload["includeDomains"] = options.IncludeDomains
	}
	if len(options.ExcludeDomains) > 0 {
		payload["excludeDomains"] = options.ExcludeDomains
	}
	if country := strings.ToUpper(strings.TrimSpace(options.UserLocation)); country != "" {
		payload["userLocation"] = country
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
	req.Header.Set("x-api-key", c.apiKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, errors.New("web search provider unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32<<10))
		return Result{}, &ProviderError{
			StatusCode: resp.StatusCode,
			Retryable:  resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500,
		}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return Result{}, errors.New("could not read web search response")
	}
	if len(raw) > maxResponseBytes {
		return Result{}, errors.New("web search response exceeded size limit")
	}
	var decoded exaResponse
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return Result{}, errors.New("web search provider returned invalid JSON")
	}
	cost, err := dollarsToMicrodollars(decoded.CostDollars.Total)
	if err != nil {
		return Result{}, errors.New("web search provider returned invalid cost")
	}
	return Result{
		RequestID:        truncateUTF8(strings.TrimSpace(decoded.RequestID), 256),
		Sources:          sanitizeSources(decoded.Results, numResults),
		CostMicrodollars: cost,
	}, nil
}

type exaResponse struct {
	RequestID   string `json:"requestId"`
	CostDollars struct {
		Total json.Number `json:"total"`
	} `json:"costDollars"`
	Results []exaResult `json:"results"`
}

type exaResult struct {
	Title         string   `json:"title"`
	URL           string   `json:"url"`
	PublishedDate string   `json:"publishedDate"`
	Author        string   `json:"author"`
	Text          string   `json:"text"`
	Summary       string   `json:"summary"`
	Highlights    []string `json:"highlights"`
}

func sanitizeSources(results []exaResult, limit int) []Source {
	if limit <= 0 || limit > maxNumResults {
		limit = maxNumResults
	}
	out := make([]Source, 0, min(len(results), limit))
	totalSnippetBytes := 0
	for _, result := range results {
		if len(out) >= limit || totalSnippetBytes >= maxTotalSnippetLen {
			break
		}
		resultURL := safeResultURL(result.URL)
		if resultURL == "" {
			continue
		}
		snippet := strings.TrimSpace(strings.Join(result.Highlights, "\n"))
		if snippet == "" {
			snippet = strings.TrimSpace(result.Summary)
		}
		if snippet == "" {
			snippet = strings.TrimSpace(result.Text)
		}
		remaining := min(MaxSnippetBytes, maxTotalSnippetLen-totalSnippetBytes)
		snippet = truncateUTF8(snippet, remaining)
		totalSnippetBytes += len(snippet)
		out = append(out, Source{
			Title:         truncateUTF8(strings.TrimSpace(result.Title), MaxTitleBytes),
			URL:           resultURL,
			PublishedDate: truncateUTF8(strings.TrimSpace(result.PublishedDate), 128),
			Author:        truncateUTF8(strings.TrimSpace(result.Author), 256),
			Snippet:       snippet,
		})
	}
	return out
}

func safeResultURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	parsed.User = nil
	return truncateUTF8(parsed.String(), 4096)
}

func dollarsToMicrodollars(value json.Number) (int, error) {
	if strings.TrimSpace(value.String()) == "" {
		return 0, nil
	}
	ratio, ok := new(big.Rat).SetString(value.String())
	if !ok || ratio.Sign() < 0 {
		return 0, errors.New("invalid dollars")
	}
	ratio.Mul(ratio, big.NewRat(1_000_000, 1))
	quotient := new(big.Int)
	remainder := new(big.Int)
	quotient.QuoRem(ratio.Num(), ratio.Denom(), remainder)
	if new(big.Int).Lsh(remainder, 1).Cmp(ratio.Denom()) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsInt64() || quotient.Int64() > int64(^uint(0)>>1) {
		return 0, errors.New("cost overflow")
	}
	return int(quotient.Int64()), nil
}

func truncateUTF8(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(value) <= maxBytes {
		return value
	}
	end := maxBytes
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end]
}
