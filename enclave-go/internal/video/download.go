package video

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func downloadVideo(
	ctx context.Context,
	httpc *http.Client,
	rawURL string,
	provider string,
	headers http.Header,
) (*PollResult, error) {
	parsed, err := validateDownloadURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%s video download: %w", provider, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%s video download: invalid request", provider)
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	client := *httpc
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		if _, err := validateDownloadURL(next.URL.String()); err != nil {
			return err
		}
		for key := range headers {
			next.Header.Del(key)
		}
		if strings.EqualFold(next.URL.Hostname(), parsed.Hostname()) {
			for key, values := range headers {
				for _, value := range values {
					next.Header.Add(key, value)
				}
			}
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s video download failed: %w", provider, err)
	}
	if err := requireProviderSuccess(provider, resp); err != nil {
		resp.Body.Close()
		return nil, err
	}
	contentType := resp.Header.Get("Content-Type")
	contentTypeLower := strings.ToLower(contentType)
	if !strings.HasPrefix(contentTypeLower, "video/") && !strings.HasPrefix(contentTypeLower, "application/octet-stream") {
		resp.Body.Close()
		return nil, fmt.Errorf("%s video download: unexpected content type", provider)
	}
	return &PollResult{
		State: PollCompleted, ProviderStatus: "COMPLETED",
		Body: resp.Body, ContentType: contentType,
	}, nil
}

func validateDownloadURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return nil, fmt.Errorf("invalid URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" {
		return nil, fmt.Errorf("unsafe URL")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()) {
		return nil, fmt.Errorf("unsafe URL")
	}
	return parsed, nil
}
