//go:build cloud_gcp

package main

import (
	"context"
	"testing"

	"golang.org/x/crypto/acme"
)

func TestGCPSingleIssuerScope(t *testing.T) {
	for host, zone := range map[string]string{"api-us-west1.quillrouter.com": "quillrouter-com", "api.trustedrouter.com": "trustedrouter-com", "api.trusted.allyrouter.com": "trustedrouter-com", "api.confidential.uptimerouter.com": "trustedrouter-com", "api.allyrouter.com": "trustedrouter-com"} {
		prod, err := singleIssuerPlan("gcp-acme-preissue", host)
		if err != nil || prod.zone != zone || prod.bucket != acmeSealedBucket || prod.directory != acme.LetsEncryptURL || prod.renew {
			t.Fatalf("bad production plan for %s", host)
		}
		stage, err := singleIssuerPlan("gcp-acme-rehearse-renew", host)
		if err != nil || !stage.renew || stage.directory == prod.directory || stage.bucket == prod.bucket || stage.record != prod.record {
			t.Fatalf("bad rehearsal plan for %s", host)
		}
		if host == "api.allyrouter.com" && prod.record != "_acme-challenge.api-allyrouter.trustedrouter.com" {
			t.Fatal("missing mirror delegation")
		}
	}
	for _, host := range []string{"api.trustedrouter.com,api.allyrouter.com", "api-aws.trustedrouter.com", "api-azure.trustedrouter.com", "*.trustedrouter.com", "api.trusted.allyrouter.com:443", "api.trusted.allyrouter.com.", "foo.test", ""} {
		if _, err := singleIssuerPlan("gcp-acme-preissue", host); err == nil {
			t.Fatalf("unexpected host allowed: %s", host)
		}
	}
	if _, err := singleIssuerPlan("gcp-acme-preissue-renew", "api.trustedrouter.com"); err == nil {
		t.Fatal("production forced renewal accepted")
	}
}

func TestGCPServingCacheRejectsStagingDirectory(t *testing.T) {
	for _, name := range []string{"QUILL_ACME_DIRECTORY_URL", "QUILL_ACME_FALLBACK_DIRECTORY_URL"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "https://acme-staging-v02.api.letsencrypt.org/directory")
			if _, err := configuredACMECache(context.Background(), nil); err == nil {
				t.Fatal("serving cache allowed staging CA")
			}
		})
	}
}
