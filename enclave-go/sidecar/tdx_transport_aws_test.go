//go:build cloud_aws

package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestIntelCollateralUsesNitroTransport(t *testing.T) {
	opts := newTDXVerificationOptions()
	getter := opts.Getter.(*intelCollateralGetter)
	transport, ok := getter.client.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil {
		t.Fatal("Intel collateral must use Nitro's vsock dialer, not direct DNS/TCP")
	}
	if transport.Proxy != nil || transport.DialTLSContext != nil {
		t.Fatal("Intel collateral must retain end-to-end TLS without an HTTP proxy or alternate TLS dialer")
	}
	_, err := transport.DialContext(context.Background(), "tcp", "unlisted.invalid:443")
	var unconfigured *unconfiguredHostError
	if !errors.As(err, &unconfigured) {
		t.Fatalf("unlisted collateral route must fail closed without DNS: %v", err)
	}
}

func TestEveryIntelCollateralAuthorityHasNitroRoute(t *testing.T) {
	want := map[string]uint32{
		"api.trustedservices.intel.com":          8051,
		"certificates.trustedservices.intel.com": 8102,
	}
	for host := range intelCollateralHosts {
		if vsockTunnels[host] == 0 || vsockTunnels[host] != want[host] {
			t.Errorf("Intel authority %s has route %d, want existing parent route %d", host, vsockTunnels[host], want[host])
		}
	}
}
