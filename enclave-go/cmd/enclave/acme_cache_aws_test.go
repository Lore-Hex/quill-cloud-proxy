//go:build cloud_aws

package main

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

func releaseCachePinMatches(measured, approved string) bool {
	raw, err := hex.DecodeString(approved)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == approved &&
		approved != strings.Repeat("0", 64) && approved == measured
}

func TestAWSReleaseCachePinValidation(t *testing.T) {
	pin := strings.Repeat("af", 32)
	for _, x := range [][2]string{{"", ""}, {"af", "af"}, {pin, ""}, {pin, strings.ToUpper(pin)}, {pin, strings.Repeat("b0", 32)}, {strings.Repeat("0", 64), strings.Repeat("0", 64)}} {
		if releaseCachePinMatches(x[0], x[1]) {
			t.Fatal("accepted missing or unapproved cache pin")
		}
	}
	if !releaseCachePinMatches(pin, pin) {
		t.Fatal("rejected matching valid pins")
	}
}

func TestAWSCompiledTLSCachePin(t *testing.T) {
	if os.Getenv("QUILL_REQUIRE_AWS_TLS_RELEASE_PIN") != "1" {
		t.Skip("only the EIF publisher has the independent release fingerprint")
	}
	if !releaseCachePinMatches(nitroTLSCacheSPKI, os.Getenv("QUILL_APPROVED_AWS_TLS_SPKI_SHA256")) {
		t.Fatal("unprovisioned or unapproved measured TLS cache identity; refusing EIF publication")
	}
}

func TestAWSCacheRejectsOtherBootstrapModes(t *testing.T) {
	for _, boot := range []*types.BootstrapData{nil, {}, {AWSBootstrap: &types.AWSBootstrapEvidence{Mode: "attested", Policy: "dual"}}, {AWSBootstrap: &types.AWSBootstrapEvidence{Mode: "legacy", Policy: "strict"}}} {
		if c, err := configuredACMECache(t.Context(), boot); c != nil || err == nil || err.Error() != "Nitro ACME requires strict attested bootstrap" {
			t.Fatal("did not reject unsupported bootstrap before key release")
		}
	}
}
