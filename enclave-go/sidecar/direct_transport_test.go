//go:build !cloud_aws

package main

import (
	"net/http"
	"testing"
)

func TestNonAWSBuildUsesDirectTLSTransport(t *testing.T) {
	before := http.DefaultTransport
	if got := installPlatformTransport(); got != "direct_tls" {
		t.Fatalf("installPlatformTransport() = %q, want direct_tls", got)
	}
	if http.DefaultTransport != before {
		t.Fatal("GCP transport unexpectedly replaced Go's direct TLS transport")
	}
}
