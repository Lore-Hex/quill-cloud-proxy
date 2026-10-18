// Package webfetch forwards only explicitly submitted URLs to DeepSeek Fetch.
// Neither the control plane nor the gateway's HTTP client visits those URLs.
package webfetch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	ModelID          = "deepseek/fetch"
	RouteType        = "tools.fetch"
	Path             = "/v1/tools/fetch"
	MaxResponseBytes = 8 << 20
	endpoint         = "https://api.deepseek.com/v1/tools/fetch"
)

type Request struct {
	URL      string                 `json:"url"`
	Model    string                 `json:"model,omitempty"`
	Provider *types.ProviderRouting `json:"provider,omitempty"`
}

type Result struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

func Parse(raw []byte) (*Request, error) {
	invalid := errors.New("Fetch requires a public HTTP(S) URL without embedded credentials (maximum 8192 characters)")
	if len(raw) > 64<<10 || !utf8.Valid(raw) {
		return nil, invalid
	}
	var req Request
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
		return nil, invalid
	}
	if req.Model == "" {
		req.Model = ModelID
	}
	if req.Model != ModelID || (req.Provider != nil && len(req.Provider.Options) != 0) {
		return nil, errors.New("Fetch supports only deepseek/fetch and does not accept provider.options")
	}
	u, err := url.Parse(req.URL)
	if err != nil || utf8.RuneCountInString(req.URL) > 8192 || u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || strings.IndexFunc(req.URL, unicode.IsSpace) >= 0 {
		return nil, invalid
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return nil, invalid
	}
	if ip := net.ParseIP(host); ip != nil && (!ip.IsGlobalUnicast() || ip.IsPrivate()) {
		return nil, invalid
	}
	return &req, nil
}

type ProviderError struct{ Status int }

func (e *ProviderError) Error() string { return "DeepSeek Fetch failed" }

type Client struct {
	http *http.Client
	key  string
}

func New(client *http.Client, key string) *Client {
	if client == nil {
		client = http.DefaultClient
	}
	copy := *client
	copy.Timeout = 60 * time.Second
	// A redirect must never forward the provider credential to another host.
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{http: &copy, key: key}
}

func (c *Client) Fetch(ctx context.Context, req *Request) (*Result, error) {
	if c.key == "" {
		return nil, &ProviderError{Status: 503}
	}
	body, _ := json.Marshal(struct {
		URL string `json:"url"`
	}{URL: req.URL})
	upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &ProviderError{Status: 502}
	}
	upstream.Header.Set("Authorization", "Bearer "+c.key)
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(upstream)
	if err != nil {
		// Transport errors can contain URLs; keep them out of logs and responses.
		return nil, &ProviderError{Status: 502}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &ProviderError{Status: resp.StatusCode}
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, &ProviderError{Status: 502}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil || len(data) > MaxResponseBytes || !utf8.Valid(data) {
		return nil, &ProviderError{Status: 502}
	}
	var result struct {
		Title   *string `json:"title"`
		Content *string `json:"content"`
	}
	if json.Unmarshal(data, &result) != nil || result.Title == nil || result.Content == nil || strings.TrimSpace(*result.Content) == "" {
		return nil, &ProviderError{Status: 502}
	}
	return &Result{Title: *result.Title, Content: *result.Content}, nil
}
