//go:build !cloud_aws

package main

import (
	"net/http"
	"time"
)

func newIntelCollateralTransport() *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// GCP Confidential Space workloads have a normal outbound network path. The
// verifier keeps Go's default end-to-end TLS transport there. Only AWS Nitro
// builds replace it with a parent-vsock byte pipe.
func installPlatformTransport() string {
	return "direct_tls"
}
