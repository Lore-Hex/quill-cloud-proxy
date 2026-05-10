//go:build !cloud_aws

// Direct (GCP confidential VM) variant of the URL-image fetch.
//
// On GCP the enclave has a normal kernel network stack, so it can do
// DNS + IP filtering + TCP dial in-process. SSRF protection
// (loopback / RFC1918 / link-local / multicast) lives here in
// safeImageDialContext and rejects before the TCP connect.
//
// On AWS Nitro the enclave has NO network at all (only vsock) so this
// path can't run; the cloud_aws build picks multimodal_aws.go which
// proxies the fetch through the TR control plane instead. The
// SSRF check then runs server-side in
// quill-router/.../routes/internal/fetch_image.py with the same
// IP-class rejection rules.

package llm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

func fetchHTTPImage(ctx context.Context, rawURL string) (string, []byte, error) {
	httpc := safeImageHTTPClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", nil, fmt.Errorf("llm/image: build image request: %w", err)
	}
	req.Header.Set("Accept", "image/png,image/jpeg")
	resp, err := httpc.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("llm/image: fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("llm/image: fetch http %d", resp.StatusCode)
	}
	mediaType := contentTypeMedia(resp.Header.Get("Content-Type"))
	data, err := readLimited(resp.Body)
	if err != nil {
		return "", nil, err
	}
	if mediaType == "" {
		mediaType = contentTypeMedia(http.DetectContentType(data))
	}
	return mediaType, data, nil
}

func safeImageHTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext: safeImageDialContext,
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxImageRedirect {
				return errors.New("llm/image: too many redirects")
			}
			if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
				return errors.New("llm/image: unsupported redirect scheme")
			}
			return nil
		},
	}
}

func safeImageDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("llm/image: invalid address")
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("llm/image: resolve failed")
	}
	for _, ip := range ips {
		if !allowedImageIP(ip) {
			continue
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	return nil, fmt.Errorf("llm/image: image host resolves to a private address")
}

func allowedImageIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() {
		as4 := ip.As4()
		if as4[0] == 169 && as4[1] == 254 {
			return false
		}
	}
	return true
}

func readLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxImageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("llm/image: read failed")
	}
	if len(data) > maxImageBytes {
		return nil, fmt.Errorf("llm/image: image too large")
	}
	return data, nil
}
