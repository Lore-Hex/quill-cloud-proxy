//go:build cloud_aws

package main

import (
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/video"
)

func videoProviderKeys(boot *types.BootstrapData) video.ProviderKeys {
	// Nitro's egress transport deliberately exposes only fixed, audited TLS
	// tunnel hosts. Native video providers return short-lived CDN hostnames,
	// so enabling them here could queue and bill a job whose content cannot be
	// relayed. Venice returns video through its fixed API host and remains safe.
	return video.ProviderKeys{Venice: boot.VeniceAPIKey}
}
