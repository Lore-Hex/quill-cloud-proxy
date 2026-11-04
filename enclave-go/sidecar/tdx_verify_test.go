package main

import (
	"net/http"
	"testing"
	"time"
)

func TestIntelCollateralTransportPreservesVerificationPolicy(t *testing.T) {
	opts := newTDXVerificationOptions()
	if !opts.GetCollateral || !opts.CheckRevocations {
		t.Fatal("Intel collateral and revocation verification must remain mandatory")
	}
	client := opts.Getter.(*intelCollateralGetter).client
	transport := client.Transport.(*http.Transport)
	if client.Timeout != 20*time.Second || transport.TLSHandshakeTimeout != 10*time.Second {
		t.Fatal("Intel collateral time limits changed")
	}
	if transport.Proxy != nil || (transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify) {
		t.Fatal("Intel collateral must retain authenticated end-to-end TLS")
	}
	if client.CheckRedirect == nil || client.CheckRedirect(&http.Request{}, nil) == nil {
		t.Fatal("Intel collateral redirects must remain forbidden")
	}
}

func TestValidateIntelCollateralURL(t *testing.T) {
	t.Parallel()
	valid := []string{
		"https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
		"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000",
		"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
	}
	for _, endpoint := range valid {
		endpoint := endpoint
		t.Run("accept_"+endpoint, func(t *testing.T) {
			t.Parallel()
			if err := validateIntelCollateralURL(endpoint); err != nil {
				t.Fatalf("validateIntelCollateralURL(%q): %v", endpoint, err)
			}
		})
	}

	invalid := []string{
		"http://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
		"https://api.trustedservices.intel.com.evil.example/quote",
		"https://user@api.trustedservices.intel.com/quote",
		"https://api.trustedservices.intel.com:443/quote",
		"https://API.trustedservices.intel.com/quote",
		"https://certificates.trustedservices.intel.com/quote#fragment",
	}
	for _, endpoint := range invalid {
		endpoint := endpoint
		t.Run("reject_"+endpoint, func(t *testing.T) {
			t.Parallel()
			if err := validateIntelCollateralURL(endpoint); err == nil {
				t.Fatalf("validateIntelCollateralURL(%q) unexpectedly succeeded", endpoint)
			}
		})
	}
}
