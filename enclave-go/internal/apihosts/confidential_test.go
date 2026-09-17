package apihosts

import (
	"strings"
	"testing"
)

func TestConfidentialHosts(t *testing.T) {
	for _, domain := range publicDomains {
		for _, host := range []string{"api.confidential." + domain, "API.CONFIDENTIAL." + strings.ToUpper(domain) + ".:443"} {
			if !Confidential(host) {
				t.Errorf("not recognized: %s", host)
			}
		}
	}
	for _, host := range []string{"api.trustedrouter.com", "api.confidential.trustedrouter.com.evil", "confidential.trustedrouter.com", "", "api.confidential.example.com"} {
		if Confidential(host) {
			t.Errorf("unexpected match: %s", host)
		}
	}
}

func TestWithConfidentialAliases(t *testing.T) {
	configured := "api.trustedrouter.com,api.quillrouter.com,api.allyrouter.com,api.uptimerouter.com,api-us-central1.quillrouter.com"
	got := WithConfidentialAliases(configured)
	if !strings.HasPrefix(got, configured+",") || len(strings.Split(got, ",")) != 9 {
		t.Fatalf("unexpected certificate names: %s", got)
	}
	if WithConfidentialAliases(got) != got {
		t.Fatal("not idempotent")
	}
	if WithConfidentialAliases("custom.example") != "custom.example" {
		t.Fatal("expanded a non-public domain")
	}
}
