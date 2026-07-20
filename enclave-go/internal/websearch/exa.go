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
	"strconv"
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
	maxCostNumberBytes = 64
	maxCostExponent    = 18
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
	raw := strings.TrimSpace(value.String())
	if raw == "" {
		return 0, nil
	}
	if len(raw) > maxCostNumberBytes || strings.HasPrefix(raw, "-") || strings.HasPrefix(raw, "+") {
		return 0, errors.New("invalid dollars")
	}

	mantissa := raw
	exponent := 0
	if exponentAt := strings.IndexAny(raw, "eE"); exponentAt >= 0 {
		if strings.IndexAny(raw[exponentAt+1:], "eE") >= 0 {
			return 0, errors.New("invalid dollars")
		}
		mantissa = raw[:exponentAt]
		parsedExponent, err := strconv.Atoi(raw[exponentAt+1:])
		if err != nil || parsedExponent < -maxCostExponent || parsedExponent > maxCostExponent {
			return 0, errors.New("invalid dollars")
		}
		exponent = parsedExponent
	}

	whole, fraction, hasDecimal := strings.Cut(mantissa, ".")
	if whole == "" || (hasDecimal && fraction == "") || strings.Contains(fraction, ".") {
		return 0, errors.New("invalid dollars")
	}
	digits := whole + fraction
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return 0, errors.New("invalid dollars")
		}
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return 0, nil
	}
	coefficient, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return 0, errors.New("invalid dollars")
	}

	// Convert exactly to microdollars, rounding half up. Both the source number
	// and exponent are tightly bounded before any arbitrary-precision work.
	shift := 6 + exponent - len(fraction)
	result := new(big.Int).Set(coefficient)
	if shift >= 0 {
		result.Mul(result, pow10(shift))
	} else {
		divisor := pow10(-shift)
		remainder := new(big.Int)
		result.QuoRem(result, divisor, remainder)
		if new(big.Int).Lsh(remainder, 1).Cmp(divisor) >= 0 {
			result.Add(result, big.NewInt(1))
		}
	}
	if !result.IsInt64() || result.Int64() > int64(^uint(0)>>1) {
		return 0, errors.New("cost overflow")
	}
	return int(result.Int64()), nil
}

func pow10(exponent int) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exponent)), nil)
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
