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
	if !strings.HasPrefix(got, configured+",") || len(strings.Split(got, ",")) != 13 {
		t.Fatalf("unexpected certificate names: %s", got)
	}
	if WithConfidentialAliases(got) != got {
		t.Fatal("not idempotent")
	}
	if WithConfidentialAliases("custom.example") != "custom.example" {
		t.Fatal("expanded a non-public domain")
	}
}

func TestChallengeDelegations(t *testing.T) {
	for _, owner := range []string{"quillrouter", "allyrouter", "uptimerouter", "nytokenexchange"} {
		host := "api.confidential." + owner + ".com"
		want := "_acme-challenge.api-confidential-" + owner + ".trustedrouter.com"
		if got := ChallengeRecord(host, "trustedrouter-com"); got != want {
			t.Fatalf("%s: %s", host, got)
		}
		if got := ChallengeRecord(host, "other-zone"); got != "" {
			t.Fatal("delegation outside the configured zone")
		}
	}
	for _, host := range []string{"api.trustedrouter.com", "api.confidential.trustedrouter.com", "untrusted.example"} {
		if ChallengeRecord(host, "trustedrouter-com") != "" {
			t.Fatal("ordinary challenge modified")
		}
	}
}

func TestNyteAPIAliases(t *testing.T) {
	configured := "api.trustedrouter.com,api.nytokenexchange.com"
	got := WithConfidentialAliases(configured)
	if got != configured+",api.confidential.trustedrouter.com,api.trusted.trustedrouter.com,api.confidential.nytokenexchange.com,api.trusted.nytokenexchange.com" {
		t.Fatalf("NYTE certificate aliases: %s", got)
	}
	if Confidential("api.nytokenexchange.com") || Confidential("api.confidential.nytokenexchange.com.evil") {
		t.Fatal("ordinary or lookalike NYTE host classified confidential")
	}
	if ChallengeRecord("api.nytokenexchange.com", "trustedrouter-com") != "_acme-challenge.api-nytokenexchange.trustedrouter.com" {
		t.Fatal("NYTE API certificate challenge is not delegated")
	}
	if ChallengeRecord("api.nytokenexchange.com", "other-zone") != "" {
		t.Fatal("NYTE challenge escaped the configured zone")
	}
}

func TestTrustedAliases(t *testing.T) {
	for _, domain := range publicDomains {
		host := "api.trusted." + domain
		if !Trusted(strings.ToUpper(host)+".:443") || Trusted(host+".example") || Trusted("api."+domain) || Confidential(host) {
			t.Fatal(domain)
		}
		if !strings.Contains(WithConfidentialAliases("api."+domain), ","+host) {
			t.Fatal("missing certificate:", host)
		}
		want := ""
		if domain != "trustedrouter.com" {
			want = "_acme-challenge.api-trusted-" + strings.TrimSuffix(domain, ".com") + ".trustedrouter.com"
		}
		if ChallengeRecord(host, "trustedrouter-com") != want || ChallengeRecord(host, "other") != "" {
			t.Fatal("incorrect ACME delegation for", host)
		}
	}
}
