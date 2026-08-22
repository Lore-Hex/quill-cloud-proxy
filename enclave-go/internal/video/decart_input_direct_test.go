//go:build !cloud_aws

package video

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
)

func TestFetchRemoteVideoValidatesAndStagesMP4(t *testing.T) {
	payload := testMP4(5_000, 1_000, false)
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://assets.example/video.mp4" {
			t.Fatalf("request URL = %s", req.URL)
		}
		return &http.Response{
			StatusCode:    200,
			Header:        http.Header{"Content-Type": []string{"video/mp4"}},
			Body:          io.NopCloser(bytes.NewReader(payload)),
			ContentLength: int64(len(payload)),
		}, nil
	})}
	body, mediaType, err := fetchRemoteVideo(
		t.Context(), "https://assets.example/video.mp4", 5, client,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if mediaType != "video/mp4" || !bytes.Equal(got, payload) {
		t.Fatalf("mediaType=%q bytes=%d", mediaType, len(got))
	}
}

func TestFetchRemoteVideoRejectsUnsafeURLBeforeTransport(t *testing.T) {
	called := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("must not dial")
	})}
	_, _, err := fetchRemoteVideo(t.Context(), "https://127.0.0.1/video.mp4", 5, client)
	if err == nil || called {
		t.Fatalf("err=%v transport_called=%t", err, called)
	}
}

func TestRemoteVideoResponseGates(t *testing.T) {
	tests := []struct {
		name          string
		contentType   string
		contentLength int64
	}{
		{name: "wrong content type", contentType: "text/plain", contentLength: 1},
		{name: "oversized", contentType: "video/mp4", contentLength: maxDecartInputVideoBytes + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{"Content-Type": []string{tt.contentType}}, ContentLength: tt.contentLength}
			if err := validateRemoteVideoResponse(resp); err == nil {
				t.Fatal("response must be rejected")
			}
		})
	}
}

func TestVideoInputRedirectRevalidatesEveryLocation(t *testing.T) {
	next, _ := http.NewRequest(http.MethodGet, "https://10.0.0.1/video.mp4", nil)
	if err := validateVideoInputRedirect(next, nil); err == nil {
		t.Fatal("private redirect must be rejected")
	}
	public, _ := http.NewRequest(http.MethodGet, "https://assets.example/video.mp4", nil)
	if err := validateVideoInputRedirect(public, []*http.Request{{}, {}, {}}); err == nil {
		t.Fatal("redirect limit must be enforced")
	}
}

func TestSafeVideoDialRejectsMixedDNSAnswersBeforeDial(t *testing.T) {
	var dialed []string
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")}, nil
	}
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		return nil, errors.New("sentinel")
	}
	_, err := safeVideoDialContextWith(t.Context(), "tcp", "assets.example:443", lookup, dial)
	if err == nil || len(dialed) != 0 {
		t.Fatalf("err=%v dialed=%v", err, dialed)
	}
}

func TestSafeVideoDialUsesOnlyVettedResolvedIP(t *testing.T) {
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	var dialed []string
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		return nil, errors.New("sentinel")
	}
	_, err := safeVideoDialContextWith(t.Context(), "tcp", "assets.example:443", lookup, dial)
	if err == nil || !reflect.DeepEqual(dialed, []string{"1.1.1.1:443"}) {
		t.Fatalf("err=%v dialed=%v", err, dialed)
	}
}

func TestAllowedVideoIPRejectsPrivateAndMetadataAddresses(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254",
		"100.64.0.1", "168.63.129.16", "198.18.0.1", "::1", "fe80::1", "fc00::1",
		"ff02::1", "0.0.0.0", "64:ff9b:1::1",
	} {
		if llm.AllowedPublicIP(netip.MustParseAddr(raw)) {
			t.Fatalf("AllowedPublicIP(%s) = true", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !llm.AllowedPublicIP(netip.MustParseAddr(raw)) {
			t.Fatalf("AllowedPublicIP(%s) = false", raw)
		}
	}
}
