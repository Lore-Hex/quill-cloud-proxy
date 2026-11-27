//go:build cloud_gcp

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/apihosts"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
	"golang.org/x/crypto/acme"
)

const rehearsalBucket = "quill-cloud-proxy-acme-rehearsal-v1"

type gcpIssuerPlan struct {
	bucket, directory, zone, record string
	renew                           bool
}

func singleIssuerPlan(mode, host string) (gcpIssuerPlan, error) {
	var p gcpIssuerPlan
	switch mode {
	case "gcp-acme-preissue":
		p.bucket, p.directory = acmeSealedBucket, acme.LetsEncryptURL
	case "gcp-acme-rehearse", "gcp-acme-rehearse-renew":
		p.bucket, p.directory = rehearsalBucket, "https://acme-staging-v02.api.letsencrypt.org/directory"
		p.renew = mode == "gcp-acme-rehearse-renew"
	default:
		return p, errors.New("unsupported issuer mode")
	}
	p.zone = "trustedrouter-com"
	// All names are exact GCP gateway names. Never accept a caller-supplied
	// directory, storage resource, DNS record target, or wildcard.
	switch host {
	case "api.trustedrouter.com", "api.nytokenexchange.com":
	case "api.allyrouter.com", "api.uptimerouter.com":
		p.record = "_acme-challenge.api-" + strings.TrimSuffix(strings.TrimPrefix(host, "api."), ".com") + ".trustedrouter.com"
	case "api.quillrouter.com", "api-us-central1.quillrouter.com", "api-us-east4.quillrouter.com", "api-us-west1.quillrouter.com", "api-europe-west4.quillrouter.com":
		p.zone = "quillrouter-com"
	default:
		if strings.ToLower(host) != host || strings.ContainsAny(host, ":/") || strings.HasSuffix(host, ".") || !(apihosts.Trusted(host) || apihosts.Confidential(host)) {
			return p, errors.New("not an exact GCP gateway hostname")
		}
	}
	if p.record == "" {
		p.record = apihosts.ChallengeRecord(host, p.zone)
	}
	return p, nil
}

func issueGCPLeaf(mode, host string) error {
	p, err := singleIssuerPlan(mode, host)
	if err != nil {
		return err
	}
	cache, err := sealedGCPCache(p.bucket)
	if err != nil {
		return errors.New("single-issuer sealed cache unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	client := enclavetls.NewDNS01HTTPClient()
	cfg := enclavetls.DNS01Config{DNSName: host, ChallengeRecord: p.record, Email: "acme@trustedrouter.com", Provider: enclavetls.NewCloudDNSProvider("quill-cloud-proxy", p.zone, client), Cache: cache, DirectoryURL: p.directory, HTTPClient: client}
	return enclavetls.PreissueDNS01(ctx, cfg, p.renew)
}

func dns01ProviderForHost(host string) (enclavetls.DNS01Provider, string) {
	zone := strings.TrimSpace(os.Getenv("QUILL_ACME_DNS_MANAGED_ZONE"))
	project := strings.TrimSpace(os.Getenv("QUILL_ACME_DNS_GCP_PROJECT"))
	if project == "quill-cloud-proxy" && zone == "trustedrouter-com" {
		if plan, err := singleIssuerPlan("gcp-acme-preissue", host); err == nil {
			return enclavetls.NewCloudDNSProvider(project, plan.zone, enclavetls.NewDNS01HTTPClient()), plan.record
		}
	}
	return dns01Provider(), apihosts.ChallengeRecord(host, zone)
}
