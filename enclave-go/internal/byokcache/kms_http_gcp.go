//go:build !cloud_aws

// Stdlib HTTP client for the BYOK Google-KMS unwrap path on the
// GCP-side enclave (and for unit tests + dev builds).
//
// On GCP/GCE the enclave has a NIC; standard DNS + TCP works and the
// metadata.google.internal endpoint mints tokens. The cloud_aws
// variant in kms_http_aws.go uses a vsock-tunneled client.
package byokcache

import (
	"net/http"
	"time"
)

// NewVsockKMSClient returns a stdlib http.Client on non-AWS builds
// (the name is shared with the cloud_aws variant; on GCP the
// "vsock" part is just history-preserving).
func NewVsockKMSClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
