//go:build cloud_aws

package main

import (
	"net/http"
	"testing"
)

func TestAWSBuildInstallsVsockTransport(t *testing.T) {
	before := http.DefaultTransport
	if got := installPlatformTransport(); got != "vsock" {
		t.Fatalf("installPlatformTransport() = %q, want vsock", got)
	}
	if http.DefaultTransport == before {
		t.Fatal("AWS transport did not replace the direct network transport")
	}
	if _, ok := vsockTunnels["inference.tinfoil.sh"]; !ok {
		t.Fatal("AWS sidecar is missing the Tinfoil verification tunnel")
	}
}
