//go:build !cloud_gcp

package main

import (
	"errors"
	"os"
	"strings"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/apihosts"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/enclavetls"
)

func dns01ProviderForHost(host string) (enclavetls.DNS01Provider, string) {
	return dns01Provider(), apihosts.ChallengeRecord(host, strings.TrimSpace(os.Getenv("QUILL_ACME_DNS_MANAGED_ZONE")))
}

func checkGCPCacheCustody() error       { return errors.New("requires GCP gateway build") }
func issueGCPLeaf(string, string) error { return errors.New("requires GCP gateway build") }
