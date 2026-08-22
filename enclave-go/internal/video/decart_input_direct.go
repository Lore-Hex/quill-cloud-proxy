//go:build !cloud_aws

package video

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

// openRemoteVideo resolves and dials the caller-supplied host itself so DNS
// rebinding cannot turn an apparently public URL into enclave metadata or a
// private service. The downloaded body is then staged and validated by the
// same bounded MP4 path used for data URLs.
func (c *DecartVideoClient) openRemoteVideo(
	ctx context.Context,
	rawURL string,
	declaredDurationSeconds int,
) (io.ReadCloser, string, error) {
	transport := &http.Transport{
		DialContext:           safeVideoDialContext,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	defer transport.CloseIdleConnections()
	timeout := c.http.Timeout
	if timeout == 0 {
		timeout = 3 * time.Minute
	}
	client := &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: validateVideoInputRedirect,
	}
	return fetchRemoteVideo(ctx, rawURL, declaredDurationSeconds, client)
}

func fetchRemoteVideo(
	ctx context.Context,
	rawURL string,
	declaredDurationSeconds int,
	client *http.Client,
) (io.ReadCloser, string, error) {
	parsed, err := validateDownloadURL(rawURL)
	if err != nil {
		return nil, "", &InputError{Message: "video input URL is invalid"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, "", fmt.Errorf("decart video input: invalid request")
	}
	req.Header.Set("Accept", "video/mp4")
	req.Header.Set("User-Agent", "TrustedRouter-VideoFetcher/1.0 (+https://trustedrouter.com)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", &InputError{Message: "video input could not be fetched"}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		resp.Body.Close()
		return nil, "", &InputError{Message: "video input could not be fetched"}
	}
	if err := validateRemoteVideoResponse(resp); err != nil {
		resp.Body.Close()
		return nil, "", err
	}
	return spoolDecartVideo(resp.Body, declaredDurationSeconds, maxDecartInputVideoBytes)
}

func validateVideoInputRedirect(next *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return fmt.Errorf("too many redirects")
	}
	_, err := validateDownloadURL(next.URL.String())
	return err
}

func validateRemoteVideoResponse(resp *http.Response) error {
	if resp.ContentLength > maxDecartInputVideoBytes {
		return &InputError{Message: "video input exceeds the size limit"}
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "video/mp4") {
		return &InputError{Message: "video input must be MP4"}
	}
	return nil
}

func safeVideoDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	return safeVideoDialContextWith(
		ctx, network, address, net.DefaultResolver.LookupNetIP, dialer.DialContext,
	)
}

type videoLookupNetIP func(context.Context, string, string) ([]netip.Addr, error)
type videoDialContext func(context.Context, string, string) (net.Conn, error)

func safeVideoDialContextWith(
	ctx context.Context,
	network, address string,
	lookup videoLookupNetIP,
	dial videoDialContext,
) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("decart video input: invalid address")
	}
	ips, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("decart video input: resolve failed")
	}
	for _, ip := range ips {
		if !llm.AllowedPublicIP(ip) {
			return nil, fmt.Errorf("decart video input: host resolves to a non-public address")
		}
	}
	for _, ip := range ips {
		conn, dialErr := dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if dialErr == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("decart video input: public host is unreachable")
}
