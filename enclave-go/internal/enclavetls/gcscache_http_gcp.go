//go:build !cloud_aws

// Standard HTTP client for the GCS-backed autocert cache on the
// GCP-side enclave (and for unit tests + dev builds).
//
// On GCP / GCE the enclave has a real NIC and a default ADC chain via
// metadata.google.internal; no vsock tunnel is needed. This file's
// `!cloud_aws` build constraint means it ships with every build target
// other than the AWS Nitro one — the cloud_aws variant in
// gcscache_http_aws.go provides the vsock-tunneled equivalent.
package enclavetls

import (
	"net/http"
	"time"
)

func newCacheHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func newTokenHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
