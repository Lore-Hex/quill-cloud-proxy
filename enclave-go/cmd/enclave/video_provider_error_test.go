package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

// A provider's own HTTP rejection must not read as a router failure: the
// daily grok video canary reported xAI's HTTP 400 as router_error because
// every video failure was labelled source "router".
func TestVideoProviderErrorNamesWhoFailed(t *testing.T) {
	cases := []struct {
		name                         string
		err                          error
		status                       string
		source, errType, code, param string
	}{
		{"provider_rejection", &video.HTTPError{Provider: "grok", Status: 400}, "400", "provider", "provider_error", "video_provider_error", ""},
		{"wrapped_provider_rate_limit", fmt.Errorf("queue: %w", &video.HTTPError{Provider: "grok", Status: 429, Retryable: true}), "429", "provider", "provider_error", "rate_limit_exceeded", ""},
		{"provider_outage", &video.HTTPError{Provider: "runway", Status: 503, Retryable: true}, "503", "provider", "provider_error", "video_provider_error", ""},
		{"local_failure", errors.New("xai video provider does not support this request"), "502", "router", "provider_error", "video_provider_error", ""},
		{"caller_input", &video.InputError{Message: "reference image could not be fetched"}, "400", "router", "invalid_request_error", "invalid_video_input", "input_references"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			writeVideoProviderError(&out, tc.err, "video provider rejected the job")
			if !strings.HasPrefix(out.String(), "HTTP/1.1 "+tc.status+" ") {
				t.Fatalf("response = %s", out.String())
			}
			failure := videoHTTPBody(t, out.String())["error"].(map[string]any)
			if failure["source"] != tc.source || failure["type"] != tc.errType || failure["code"] != tc.code {
				t.Fatalf("error = %#v", failure)
			}
			if tc.param == "" && failure["param"] != nil || tc.param != "" && failure["param"] != tc.param {
				t.Fatalf("param = %#v", failure["param"])
			}
		})
	}
}

func TestOpenAIErrorStaysRouterSourced(t *testing.T) {
	var out bytes.Buffer
	writeOpenAIError(&out, 400, "invalid video provider preferences", "invalid_request_error", "bad_request", "provider")
	failure := videoHTTPBody(t, out.String())["error"].(map[string]any)
	if failure["source"] != "router" || failure["param"] != "provider" {
		t.Fatalf("error = %#v", failure)
	}
}
